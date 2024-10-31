#include <drogon/drogon.h>
#include <json/json.h>

const std::string CLIENT_ID = "your_client_id";
const std::string CLIENT_SECRET = "your_client_secret";
const std::string REDIRECT_URI = "http://localhost:8080/callback";

void handleGoogleOAuth2(const drogon::HttpRequestPtr& req, std::function<void(const drogon::HttpResponsePtr&)>&& callback) 
{
    std::string authUrl = "https://accounts.google.com/o/oauth2/auth?client_id=" + CLIENT_ID +
        "&redirect_uri=" + REDIRECT_URI +
        "&response_type=code&scope=email%20profile";

    auto resp = drogon::HttpResponse::newRedirectionResponse(authUrl);
    callback(resp);
}

void handleGoogleCallback(const drogon::HttpRequestPtr& req, std::function<void(const drogon::HttpResponsePtr&)>&& callback) 
{
    std::string code = req->getParameter("code");

    if (!code.empty()) 
    {
        // Exchange authorization code for access token
        drogon::HttpClientPtr client = drogon::HttpClient::newHttpClient("https://oauth2.googleapis.com");

        std::string postData = "client_id=" + CLIENT_ID +
                               "&client_secret=" + CLIENT_SECRET +
                               "&redirect_uri=" + REDIRECT_URI +
                               "&grant_type=authorization_code" +
                               "&code=" + code;

        auto formReq = drogon::HttpRequest::newHttpRequest();
        formReq->setPath("/token");
        formReq->setMethod(drogon::Post);
        formReq->setContentTypeCode(drogon::ContentType::CT_APPLICATION_X_FORM);
        formReq->setBody(postData);

        client->sendRequest(formReq, [callback](drogon::ReqResult result, const drogon::HttpResponsePtr& resp) {
            if (result == drogon::ReqResult::Ok && resp->getStatusCode() == drogon::HttpStatusCode::k200OK) 
            {
                Json::CharReaderBuilder builder; 
                Json::CharReader* reader = builder.newCharReader();
                Json::Value tokenJson;
                std::string errs;
                if (reader->parse(resp->getBody().data(), resp->getBody().data() + resp->getBody().size(), &tokenJson, &errs)) 
                {
                    std::string accessToken = tokenJson["access_token"].asString();

                    // Use access token to fetch user info
                    drogon::HttpClientPtr userInfoClient = drogon::HttpClient::newHttpClient("https://www.googleapis.com");

                    auto reqUserInfo = drogon::HttpRequest::newHttpRequest();
                    reqUserInfo->setPath("/oauth2/v1/userinfo?access_token=" + accessToken);

                    userInfoClient->sendRequest(reqUserInfo, [callback](drogon::ReqResult userInfoResult, const drogon::HttpResponsePtr& userInfoResp) {
                        if (userInfoResult == drogon::ReqResult::Ok && userInfoResp->getStatusCode() == drogon::HttpStatusCode::k200OK) 
                        {
                            auto resp = drogon::HttpResponse::newHttpResponse();
                            resp->setContentTypeCode(drogon::CT_APPLICATION_JSON);
                            resp->setBody(std::string(userInfoResp->getBody()));
                            callback(resp);
                        }
                        else 
                        {
                            auto resp = drogon::HttpResponse::newHttpResponse();
                            resp->setBody("Failed to fetch user info");
                            callback(resp);
                        }
                        });
                }
                else 
                { 
                    auto resp = drogon::HttpResponse::newHttpResponse(); 
                    resp->setBody("Failed to parse token response: " + errs); 
                    callback(resp); 
                }
                delete reader;
            }
            else 
            {
                auto resp = drogon::HttpResponse::newHttpResponse();
                resp->setBody("Failed to exchange code for token");
                callback(resp);
            }
        });
    }
    else 
    {
        auto resp = drogon::HttpResponse::newHttpResponse();
        resp->setBody("No authorization code provided");
        callback(resp);
    }
}

int main()
{
    // Create a simple Drogon application
    auto& app = drogon::app().addListener("0.0.0.0", 8080);

    // Add a handler for Google OAuth2 authentication
    app.registerHandler("/auth/google", &handleGoogleOAuth2);

    // Add a handler for the OAuth2 callback
    app.registerHandler("/callback", &handleGoogleCallback);

    // Run the application
    app.run();

    return 0;
}
