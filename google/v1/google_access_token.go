package PTGUgoogle

import (
	"context"
	"time"

	"golang.org/x/oauth2/google"
	"golang.org/x/oauth2/jwt"

	"github.com/pkg/errors"
)


func (receiver googleReceiverArgument) GenerateGoolgeAccessTokenWithoutOAuth(ctx context.Context) (string, error) {
	authUrl := "https://accounts.google.com/o/oauth2/token"
	now := time.Now()
	conf := &jwt.Config{
		Email:        receiver.googleConfig.GenerateAccessToken.ClientEmail,
		PrivateKey:   []byte(receiver.googleConfig.GenerateAccessToken.PrivateKey),
		PrivateKeyID: receiver.googleConfig.GenerateAccessToken.PrivateKeyID,
		Scopes:       receiver.googleConfig.GenerateAccessToken.Scopes,
		TokenURL:     google.JWTTokenURL,
		Audience:     authUrl,
		Expires:      time.Duration(now.Add(1 * time.Hour).Unix()),
	}

	token, err := conf.TokenSource(ctx).Token()
	if err != nil {
		return "", errors.Wrap(err, "[Error][PTGUgoogle][Google.GenerateGoolgeAccessTokenWithoutOAuth()]->Get access token with out oauth error")
	}

	return token.AccessToken, nil
}
