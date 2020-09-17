use super::State;
use crate::{server_server, ConduitResult, Database, Error, Ruma};
use ruma::api::{
    client::{
        error::ErrorKind,
        r0::alias::{create_alias, delete_alias, get_alias},
    },
    federation,
};

#[cfg(feature = "conduit_bin")]
use rocket::{delete, get, put};

use rocket::{
    http::RawStr,
    response::{Flash, Redirect},
    uri,
};

use openid::{Token, Userinfo};

const MAC_VALID_SECS: i64 = 10;

#[cfg_attr(
    feature = "conduit_bin",
    get("/_matrix/client/r0/login/sso/redirect?<redirectUrl>")
)]
pub async fn get_sso_redirect(db: State<'_, Database>, redirectUrl: &RawStr) -> Redirect {
    let client = db.globals.openid_client.as_ref().unwrap();

    // https://docs.rs/openid/0.4.0/openid/struct.Options.html
    let auth_url = client.auth_url(&openid::Options {
        scope: Some("email".into()), // TODO: openid only?
        //TODO: nonce?
        ..Default::default()
    });

    Redirect::to(auth_url.to_string())
}

async fn request_token(
    oidc_client: &openid::DiscoveredClient,
    code: &str,
) -> Result<Option<(Token, Userinfo)>, Error> {
    let mut token: Token = oidc_client.request_token(&code).await.unwrap().into();
    if let Some(mut id_token) = token.id_token.as_mut() {
        oidc_client.decode_token(&mut id_token).unwrap();
        oidc_client.validate_token(&id_token, None, None).unwrap();
    // eprintln!("token: {:?}", id_token);
    } else {
        return Ok(None);
    }
    let userinfo = oidc_client.request_userinfo(&token).await.unwrap();

    // eprintln!("user info: {:?}", userinfo);
    Ok(Some((token, userinfo)))
}

#[derive(Debug)]
struct User {
    id: String,
    login: Option<String>,
    first_name: Option<String>,
    last_name: Option<String>,
    email: Option<String>,
    image_url: Option<String>,
    activated: bool,
    lang_key: Option<String>,
    authorities: Vec<String>,
}

#[cfg_attr(feature = "conduit_bin", get("/sso_return?<session_state>&<code>"))]
pub async fn get_sso_return<'a>(
    db: State<'_, Database>,
    session_state: &RawStr,
    code: &RawStr,
) -> Redirect {
    let client = db.globals.openid_client.as_ref().unwrap();

    let mut user2 = None;

    match request_token(client, code).await {
        Ok(Some((token, userinfo))) => {
            let id = uuid::Uuid::new_v4().to_string();

            let login = userinfo.preferred_username.clone();
            let email = userinfo.email.clone();

            let user = User {
                id: userinfo.sub.clone().unwrap_or_default(),
                login,
                last_name: userinfo.family_name.clone(),
                first_name: userinfo.name.clone(),
                email,
                activated: userinfo.email_verified,
                image_url: userinfo.picture.clone().map(|x| x.to_string()),
                lang_key: Some("en".to_string()),
                authorities: vec!["ROLE_USER".to_string()], //FIXME: read from token
            };

            // println!("user: {:#?}", user);
            user2 = user.login;
        }
        Ok(None) => {
            eprintln!("login error in call: no id_token found");

            // HttpResponse::Unauthorized().finish()
        }
        Err(err) => {
            eprintln!("login error in call: {:?}", err);

            // HttpResponse::Unauthorized().finish()
        }
    }

    use macaroon::{Macaroon, Verifier};

    let id = user2.unwrap();

    // Create our macaroon
    let mut macaroon =
        match Macaroon::create(Some("location".into()), &db.globals.macaroon_key, id.into()) {
            Ok(macaroon) => macaroon,
            Err(error) => panic!("Error creating macaroon: {:?}", error),
        };

    let timestamp = chrono::Utc::now().timestamp();

    let something = format!("time < {}", timestamp + MAC_VALID_SECS).into();
    macaroon.add_first_party_caveat(something);

    let m2 = macaroon.serialize(macaroon::Format::V2).unwrap();

    let m3 = base64::encode_config(m2, base64::URL_SAFE_NO_PAD);

    Redirect::to(format!("http://localhost:8080?loginToken={}", m3))
}
