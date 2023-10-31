package PTGUgoogle

type GoogleConfig struct {
	GenerateAccessToken GoogleConfigGenerateAccessToken
	AccessToken         string
}

type GoogleConfigGenerateAccessToken struct {
	// Client Email from service account json file
	ClientEmail string

	// Private Key ID from service account json file
	PrivateKeyID string

	// Private Key from service account json file
	// PrivateKey contains the contents of an RSA private key or the
	// contents of a PEM file that contains a private key. The provided
	// private key is used to sign JWT payloads.
	// PEM containers with a passphrase are not supported.
	// Use the following command to convert a PKCS 12 file into a PEM.
	//
	//    $ openssl pkcs12 -in key.p12 -out key.pem -nodes
	//
	PrivateKey string

	// Scopes optionally specifies a list of requested permission scopes.
	Scopes []string
}

type googleReceiverArgument struct {
	googleConfig *GoogleConfig
}

func NewGoogle(inputConfig *GoogleConfig) *googleReceiverArgument {
	return &googleReceiverArgument{
		googleConfig: inputConfig,
	}
}
