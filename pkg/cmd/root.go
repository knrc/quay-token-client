package cmd

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/knrc/quay-token-client/pkg/client"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	quayURL     string
	username    string
	password    string
	serviceName string
	keyID       string
	expiry      time.Duration
	delete      bool
	testDocker  bool
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "quay-token-client",
	Short: "A client for creating a new RSA service key.",
	Long: `Creates and approve a new RSA service key.

Example:
  quay-token-client --quay-url https://your-quay.com \
                    --username admin --password password \
                    --service-name test-service --key-id test-key`,
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg := client.Config{
			QuayURL:  quayURL,
			Username: username,
			Password: password,
		}

		if cfg.QuayURL == "" || cfg.Username == "" || cfg.Password == "" {
			return fmt.Errorf("Error: QUAY_URL, QUAY_USERNAME, and QUAY_PASSWORD must be provided either via flags or environment variables.")
		}

		cli, err := client.NewClient(cfg)
		if err != nil {
			log.Fatalf("Failed to create client: %v", err)
		}

		log.Println("Attempting to retrieve CSRF for login...")
		if err := cli.GetCSRF(); err != nil {
			log.Fatalf("Failed to get CSRF: %v", err)
		}

		log.Println("Attempting to login to Quay...")
		if err := cli.Login(); err != nil {
			log.Fatalf("Failed to login: %v", err)
		}

		log.Println("Attempting to retrieve CSRF after login...")
		if err := cli.GetCSRF(); err != nil {
			log.Fatalf("Failed to get CSRF: %v", err)
		}

		log.Println("Looking for existing key")
		jwk, err := cli.GetServiceKey(serviceName, keyID)
		if delete && (jwk != nil || err == client.ErrServiceKeyExpired || err == client.ErrServiceKeyNotApproved) {
			log.Printf("Deleting service key '%s'...", keyID)
			if err := cli.DeleteServiceKey(keyID); err != nil {
				log.Fatalf("Failed to delete service key: %v", err)
			}
		} else {
			if err != nil {
				log.Fatalf("Error checking for existing service key: %v", err)
			}
			if jwk != nil {
				log.Fatalf("Service Key already exists")
			}
		}

		log.Println("Generating RSA key pair...")
		privateKey, publicKeyJWK, err := client.GenerateRSAKeyPair()
		if err != nil {
			log.Fatalf("Failed to generate RSA key pair: %v", err)
		}

		log.Printf("Creating service key '%s' for service '%s'...", keyID, serviceName)
		if err := cli.CreateServiceKey(serviceName, keyID, expiry, privateKey, publicKeyJWK); err != nil {
			log.Fatalf("Failed to create service key: %v", err)
		}

		log.Printf("Approving service key '%s'...", keyID)
		if err := cli.ApproveServiceKey(keyID); err != nil {
			log.Fatalf("Failed to approve service key: %v", err)
		}

		log.Println("Service key operations completed successfully.")

		if testDocker {
			log.Println("Generating Docker V2 JWT and listing repositories...")
			// KEV dummy repository permissions for now, will need to link with user/team settings
			dockerToken, err := cli.GenerateDockerV2JWT(privateKey, serviceName, keyID, username, "repository:samuser/samrepo:pull,push")
			if err != nil {
				log.Fatalf("Failed to generate Docker V2 JWT: %v", err)
			}
			log.Printf("Docker V2 Token: %s", dockerToken)

			repositories, err := cli.ListRepositories(dockerToken)
			if err != nil {
				log.Fatalf("Failed to list repositories: %v", err)
			}
			log.Printf("Successfully listed repositories: %v", repositories.Repositories)
		}
		return nil
	},
}

func Execute() {
	cobra.CheckErr(rootCmd.Execute())
}

func init() {
	cobra.OnInitialize(initConfig)

	// Define flags and bind them to viper
	definePersistentString(&quayURL, "quay-url", "q", "", "Quay URL (e.g., https://quay.io/repository/)")
	definePersistentString(&username, "username", "u", "", "Quay admin username")
	definePersistentString(&password, "password", "p", "", "Quay admin password")
	definePersistentString(&serviceName, "service-name", "s", "", "Name of the service for the key")
	definePersistentString(&keyID, "key-id", "k", "", "ID for the new service key, should be unique otherwise old versions may be retrieved from the cache")

	rootCmd.PersistentFlags().DurationVarP(&expiry, "expiry", "e", 0, "Expiry of the service key, defaults to no-expiry")
	_ = viper.BindPFlag("expiry", rootCmd.PersistentFlags().Lookup("expiry"))

	rootCmd.PersistentFlags().BoolVarP(&delete, "delete", "d", false, "Delete token after approval")
	_ = viper.BindPFlag("delete", rootCmd.PersistentFlags().Lookup("delete"))

	rootCmd.PersistentFlags().BoolVarP(&testDocker, "test-docker", "t", false, "Test Docker V2 token generation and repository listing")
	_ = viper.BindPFlag("test-docker", rootCmd.PersistentFlags().Lookup("test-docker"))

	rootCmd.MarkPersistentFlagRequired("service-name")
	rootCmd.MarkPersistentFlagRequired("key-id")

	// Set environment variable prefixes
	viper.SetEnvPrefix("QUAY")
	viper.AutomaticEnv()
}

func definePersistentString(p *string, name, shorthand, value, usage string) {
	rootCmd.PersistentFlags().StringVarP(p, name, shorthand, value, usage)
	_ = viper.BindPFlag(name, rootCmd.PersistentFlags().Lookup(name))
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
	}

	// Populate variables from viper after reading config and env
	viperQuayURL := viper.GetString("quay-url")
	if viperQuayURL != "" {
		quayURL = viperQuayURL
	}
	viperUsername := viper.GetString("username")
	if viperUsername != "" {
		username = viperUsername
	}
	viperPassword := viper.GetString("password")
	if viperPassword != "" {
		password = viperPassword
	}
	viperServiceName := viper.GetString("service-name")
	if viperServiceName != "" {
		serviceName = viperServiceName
	}
	viperKeyID := viper.GetString("key-id")
	if viperKeyID != "" {
		keyID = viperKeyID
	}
	viperExpiry := viper.GetDuration("expiry")
	if viperExpiry != 0 {
		expiry = viperExpiry
	}
	if viper.IsSet("delete") {
		delete = viper.GetBool("delete")
	}
	if viper.IsSet("test-docker") {
		testDocker = viper.GetBool("test-docker")
	}
}
