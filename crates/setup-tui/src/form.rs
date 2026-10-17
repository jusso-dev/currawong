//! Form state and key handling, kept apart from the terminal so it can be tested.
use crate::answers::Answers;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Key {
    Char(char),
    Backspace,
    Enter,
    Tab,
    BackTab,
    Up,
    Down,
    Esc,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Action {
    None,
    Submit,
    Quit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Text,
    Secret,
    Toggle,
}

pub struct Field {
    pub label: &'static str,
    pub help: &'static str,
    pub kind: Kind,
    pub value: String,
    pub on: bool,
}

const HOSTNAME: usize = 0;
const DOMAINS: usize = 1;
const NEXT_HOP: usize = 2;
const RELAY: usize = 3;
const CLAMD: usize = 4;
const NEW_CERT: usize = 5;
const PASSWORD: usize = 6;
const CONFIRM: usize = 7;
const MIN_PASSWORD: usize = 8;

pub struct Form {
    pub fields: Vec<Field>,
    /// Index into `fields`; `fields.len()` is the Save button.
    pub focus: usize,
    pub error: Option<String>,
}

fn text(label: &'static str, help: &'static str, value: &str) -> Field {
    Field {
        label,
        help,
        kind: Kind::Text,
        value: value.to_string(),
        on: false,
    }
}

fn toggle(label: &'static str, help: &'static str, on: bool) -> Field {
    Field {
        label,
        help,
        kind: Kind::Toggle,
        value: String::new(),
        on,
    }
}

fn secret(label: &'static str, help: &'static str) -> Field {
    Field {
        label,
        help,
        kind: Kind::Secret,
        value: String::new(),
        on: false,
    }
}

impl Form {
    /// `firstboot` adds the root password fields. A new certificate is
    /// offered by default only when none exists yet.
    pub fn new(firstboot: bool, hostname: &str, cert_exists: bool) -> Self {
        let mut fields = vec![
            text(
                "Hostname",
                "Gateway name for EHLO, Received and Authentication-Results.",
                hostname,
            ),
            text(
                "Domains",
                "Domains this gateway accepts mail for, separated by commas or spaces.",
                "",
            ),
            text(
                "Next hop",
                "Where clean mail goes: host or host:port, e.g. tenant.mail.protection.outlook.com.",
                "",
            ),
            text(
                "Relay networks",
                "CIDRs allowed to send outbound mail on 587 and 465. May be empty.",
                "10.0.0.0/8",
            ),
            toggle(
                "Use local clamd",
                "Scan with ClamAV on /run/clamav/clamd.ctl. If it is down, mail is deferred.",
                true,
            ),
            toggle(
                "New certificate",
                "Write a self-signed certificate for the hostname. Replace it with a CA-issued one.",
                !cert_exists,
            ),
        ];
        if firstboot {
            fields.push(secret(
                "Root password",
                "Console password for root, at least 8 characters.",
            ));
            fields.push(secret("Confirm password", "Type the root password again."));
        }
        Self {
            fields,
            focus: 0,
            error: None,
        }
    }

    pub fn on_save(&self) -> bool {
        self.focus == self.fields.len()
    }

    pub fn handle(&mut self, key: Key) -> Action {
        let last = self.fields.len();
        match key {
            Key::Esc => return Action::Quit,
            Key::Tab | Key::Down => self.focus = (self.focus + 1) % (last + 1),
            Key::BackTab | Key::Up => self.focus = (self.focus + last) % (last + 1),
            Key::Enter if self.on_save() => return Action::Submit,
            Key::Enter => self.focus += 1,
            Key::Char(' ') if !self.on_save() && self.fields[self.focus].kind == Kind::Toggle => {
                let field = &mut self.fields[self.focus];
                field.on = !field.on;
            }
            Key::Char(ch) if !self.on_save() && self.fields[self.focus].kind != Kind::Toggle => {
                if !ch.is_control() {
                    self.fields[self.focus].value.push(ch);
                }
            }
            Key::Backspace if !self.on_save() => {
                self.fields[self.focus].value.pop();
            }
            _ => {}
        }
        Action::None
    }

    pub fn answers(&self) -> Result<Answers, String> {
        Answers::parse(
            &self.fields[HOSTNAME].value,
            &self.fields[DOMAINS].value,
            &self.fields[NEXT_HOP].value,
            &self.fields[RELAY].value,
            self.fields[CLAMD].on,
        )
    }

    pub fn new_cert(&self) -> bool {
        self.fields[NEW_CERT].on
    }

    /// The root password on first boot, `None` otherwise.
    pub fn root_password(&self) -> Result<Option<&str>, String> {
        if self.fields.len() <= PASSWORD {
            return Ok(None);
        }
        let password = &self.fields[PASSWORD].value;
        if password.chars().count() < MIN_PASSWORD {
            return Err(format!("Root password: at least {MIN_PASSWORD} characters"));
        }
        if password != &self.fields[CONFIRM].value {
            return Err("Root password: the two entries do not match".into());
        }
        Ok(Some(password))
    }

    /// Validate everything; on failure the error is kept for display.
    pub fn validate(&mut self) -> Option<(Answers, Option<String>)> {
        let result = self.answers().and_then(|answers| {
            let password = self.root_password()?.map(str::to_string);
            Ok((answers, password))
        });
        match result {
            Ok(ok) => {
                self.error = None;
                Some(ok)
            }
            Err(err) => {
                self.error = Some(err);
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn typed(form: &mut Form, text: &str) {
        for ch in text.chars() {
            form.handle(Key::Char(ch));
        }
    }

    fn fill(form: &mut Form) {
        form.handle(Key::Tab);
        typed(form, "example.test");
        form.handle(Key::Enter);
        typed(form, "mx.example.test:25");
    }

    #[test]
    fn typing_tabbing_and_saving() {
        let mut form = Form::new(false, "gw.example.test", false);
        fill(&mut form);
        assert_eq!(form.fields[DOMAINS].value, "example.test");
        assert_eq!(form.fields[NEXT_HOP].value, "mx.example.test:25");
        form.handle(Key::BackTab);
        form.handle(Key::Backspace);
        assert_eq!(form.fields[DOMAINS].value, "example.tes");
        typed(&mut form, "t");
        while !form.on_save() {
            assert_eq!(form.handle(Key::Tab), Action::None);
        }
        assert_eq!(form.handle(Key::Enter), Action::Submit);
        let (answers, password) = form.validate().unwrap();
        assert_eq!(answers.domains, ["example.test"]);
        assert!(answers.clamd);
        assert!(form.new_cert());
        assert_eq!(password, None);
    }

    #[test]
    fn space_toggles_and_focus_wraps() {
        let mut form = Form::new(false, "", true);
        assert!(!form.new_cert(), "existing certificate is kept by default");
        form.handle(Key::Up);
        assert!(form.on_save());
        form.handle(Key::Up);
        form.handle(Key::Char(' '));
        assert!(form.new_cert());
        form.handle(Key::Up);
        form.handle(Key::Char(' '));
        assert!(!form.fields[CLAMD].on);
        form.handle(Key::Char('x'));
        assert_eq!(
            form.fields[CLAMD].value, "",
            "typing into a toggle does nothing"
        );
        assert_eq!(form.handle(Key::Esc), Action::Quit);
    }

    #[test]
    fn invalid_input_keeps_an_error() {
        let mut form = Form::new(false, "localhost", false);
        fill(&mut form);
        assert!(form.validate().is_none());
        assert!(form.error.as_deref().unwrap().starts_with("Hostname:"));
    }

    #[test]
    fn firstboot_requires_matching_password() {
        let mut form = Form::new(true, "gw.example.test", false);
        fill(&mut form);
        form.focus = PASSWORD;
        typed(&mut form, "short");
        assert!(form.validate().is_none());
        assert!(form.error.as_deref().unwrap().contains("at least 8"));
        typed(&mut form, "-enough");
        form.handle(Key::Tab);
        typed(&mut form, "different");
        assert!(form.validate().is_none());
        assert!(form.error.as_deref().unwrap().contains("do not match"));
        form.fields[CONFIRM].value = "short-enough".into();
        let (_, password) = form.validate().unwrap();
        assert_eq!(password.as_deref(), Some("short-enough"));
        assert!(form.error.is_none());
    }
}
