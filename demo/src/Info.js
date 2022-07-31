import {OidcUserStatus, useOidc, useOidcAccessToken, useOidcIdToken, useOidcUser} from "@axa-fr/react-oidc";
import React from "react";

export const Info = () => {
    const { logout } = useOidc();
    const { idToken, idTokenPayload } = useOidcIdToken();
    const { accessToken } = useOidcAccessToken();
    const { oidcUser, oidcUserLoadingState } = useOidcUser();

    let userInfo = '';
    switch (oidcUserLoadingState){
        case OidcUserStatus.Loading:
            userInfo = <p className="card-text">User Information are loading</p>;
        case OidcUserStatus.LoadingError:
            userInfo = <p className="card-text">Fail to load user information</p>;
        default:
            userInfo = <pre className="card-text">{JSON.stringify(oidcUser, null, 2)}</pre>;
    }

    return (
        <div className="container-fluid mt-3">
            <div className="card">
                <div className="card-body">
                    <h5 className="card-title">Welcome !!!</h5>
                    <p className="card-text">React Demo Application protected by OpenId Connect</p>
                    <button type="button" className="btn btn-primary" onClick={() => logout()}>logout</button>
                </div>
            </div>
            <div className="card text-white bg-info mb-3">
                <div className="card-body">
                    <h5 className="card-title">Access Token</h5>
                    {<p className="card-text">{accessToken}</p>}
                </div>
            </div>
            <div className="card text-white bg-info mb-3">
                <div className="card-body">
                    <h5 className="card-title">ID Token</h5>
                    {<p className="card-text">{idToken}</p>}
                    {idTokenPayload != null && <pre className="card-text">{JSON.stringify(idTokenPayload, null, 2)}</pre>}
                </div>
            </div>
            <div className="card text-white bg-info mb-3">
                <div className="card-body">
                    <h5 className="card-title">User information</h5>
                    {userInfo}
                </div>
            </div>
        </div>
    )
}