//! Digest-link and release endpoints. The admin server (#39) mounts
//! [`router`] and, once it has authenticated a request, puts a [`Principal`]
//! in its extensions. Admin routes without one answer 401. Digest links carry
//! their own authority.
//!
//! `GET` on a link only shows a confirmation page, so a mail scanner that
//! follows links cannot release or delete anything; the form `POST`s back.
use crate::{LinkAction, LinkSigner, ListQuery, Page, Principal, QuarantineError, QuarantineStore};
use askama::Template;
use axum::{
    extract::{FromRequestParts, Path, Query, State},
    http::{header, request::Parts, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use currawong_spool::Spool;
use serde::Deserialize;
use std::sync::Arc;
use time::OffsetDateTime;

#[derive(Clone)]
pub struct HttpState {
    pub store: QuarantineStore,
    pub spool: Arc<Spool>,
    pub links: LinkSigner,
}

pub fn router(state: HttpState) -> Router {
    Router::new()
        .route("/quarantine/link/{token}", get(confirm).post(follow))
        .route("/quarantine/items", get(list))
        .route("/quarantine/items/{id}/release", post(release))
        .route("/quarantine/items/{id}/delete", post(delete))
        .with_state(state)
}

/// The authenticated caller, from request extensions.
pub struct Caller(pub Principal);

impl<S: Send + Sync> FromRequestParts<S> for Caller {
    type Rejection = StatusCode;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<Principal>()
            .cloned()
            .map(Caller)
            .ok_or(StatusCode::UNAUTHORIZED)
    }
}

fn status(err: &QuarantineError) -> StatusCode {
    match err {
        QuarantineError::NotFound => StatusCode::NOT_FOUND,
        QuarantineError::Forbidden => StatusCode::FORBIDDEN,
        QuarantineError::BadRequest(_) | QuarantineError::Link(crate::LinkError::Invalid) => {
            StatusCode::BAD_REQUEST
        }
        QuarantineError::Conflict => StatusCode::CONFLICT,
        QuarantineError::Link(crate::LinkError::Expired) | QuarantineError::LinkUsed => {
            StatusCode::GONE
        }
        QuarantineError::Store(_) => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

/// Store errors are logged, not shown.
fn public_message(err: &QuarantineError) -> String {
    if let QuarantineError::Store(detail) = err {
        tracing::error!(%detail, "quarantine request failed");
        return "the quarantine is unavailable, try again later".into();
    }
    err.to_string()
}

impl IntoResponse for QuarantineError {
    fn into_response(self) -> Response {
        let body = serde_json::json!({ "error": public_message(&self) });
        (status(&self), Json(body)).into_response()
    }
}

#[derive(Template)]
#[template(path = "link.html")]
struct LinkPage<'a> {
    message: &'a str,
    button: Option<&'a str>,
}

/// Link pages: never cached, never framed, and the token in the URL is not
/// sent on as a referrer.
fn page(code: StatusCode, message: &str, button: Option<&str>) -> Response {
    let html = LinkPage { message, button }
        .render()
        .unwrap_or_else(|_| "quarantine".into());
    (
        code,
        [
            (header::CACHE_CONTROL, "no-store"),
            (header::REFERRER_POLICY, "no-referrer"),
            (
                header::CONTENT_SECURITY_POLICY,
                "default-src 'none'; form-action 'self'; frame-ancestors 'none'",
            ),
        ],
        Html(html),
    )
        .into_response()
}

fn link_error(err: &QuarantineError) -> Response {
    let message = match err {
        QuarantineError::Forbidden => "This message can only be released by an administrator.",
        QuarantineError::NotFound => "This message is no longer in quarantine.",
        QuarantineError::Conflict => "This message was already released or deleted.",
        QuarantineError::Link(crate::LinkError::Expired) => "This link has expired.",
        QuarantineError::LinkUsed => "This link was already used.",
        QuarantineError::Store(_) => {
            public_message(err);
            "The quarantine is unavailable. Try again later."
        }
        _ => "This link is not valid.",
    };
    page(status(err), message, None)
}

async fn confirm(State(state): State<HttpState>, Path(token): Path<String>) -> Response {
    let now = OffsetDateTime::now_utc();
    let found = state
        .links
        .verify(&token, now.unix_timestamp())
        .map_err(QuarantineError::from)
        .and_then(|verified| {
            let item = state.store.get(&verified.link.item_id)?;
            Ok((verified, item.ok_or(QuarantineError::NotFound)?))
        });
    let (verified, item) = match found {
        Ok(found) => found,
        Err(err) => return link_error(&err),
    };
    let (verb, button) = match verified.link.action {
        LinkAction::Release => ("Release", "Release and deliver"),
        LinkAction::Delete => ("Delete", "Delete"),
    };
    let message = format!(
        "{verb} the message \"{}\" from {}?",
        item.subject, item.sender
    );
    page(StatusCode::OK, &message, Some(button))
}

async fn follow(State(state): State<HttpState>, Path(token): Path<String>) -> Response {
    let now = OffsetDateTime::now_utc();
    match state
        .store
        .act_on_link(&state.spool, &state.links, &token, now)
        .await
    {
        Ok((_, LinkAction::Release)) => page(
            StatusCode::OK,
            "The message was released and will be delivered shortly.",
            None,
        ),
        Ok((_, LinkAction::Delete)) => page(StatusCode::OK, "The message was deleted.", None),
        Err(err) => link_error(&err),
    }
}

/// `?queue=&sender=&recipient=&subject=&since=&until=&cursor=&limit=`
async fn list(
    State(state): State<HttpState>,
    Caller(principal): Caller,
    Query(query): Query<ListQuery>,
) -> Result<Json<Page>, QuarantineError> {
    state.store.list(&principal, &query).map(Json)
}

#[derive(Debug, Default, Deserialize)]
struct ActionBody {
    reason: Option<String>,
}

async fn release(
    State(state): State<HttpState>,
    Caller(principal): Caller,
    Path(id): Path<String>,
    Json(body): Json<ActionBody>,
) -> Result<Json<serde_json::Value>, QuarantineError> {
    let released = state
        .store
        .act(
            &state.spool,
            &principal,
            &id,
            LinkAction::Release,
            body.reason.as_deref(),
            OffsetDateTime::now_utc(),
        )
        .await?;
    Ok(Json(serde_json::json!({
        "released": released.map(|id| id.to_string()),
    })))
}

async fn delete(
    State(state): State<HttpState>,
    Caller(principal): Caller,
    Path(id): Path<String>,
    Json(body): Json<ActionBody>,
) -> Result<Json<serde_json::Value>, QuarantineError> {
    state
        .store
        .act(
            &state.spool,
            &principal,
            &id,
            LinkAction::Delete,
            body.reason.as_deref(),
            OffsetDateTime::now_utc(),
        )
        .await?;
    Ok(Json(serde_json::json!({ "deleted": id })))
}
