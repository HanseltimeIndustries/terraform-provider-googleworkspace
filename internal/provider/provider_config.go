// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package googleworkspace

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/hashicorp/go-cleanhttp"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"

	"golang.org/x/oauth2"
	googleoauth "golang.org/x/oauth2/google"

	"cloud.google.com/go/auth/credentials"
	directory "google.golang.org/api/admin/directory/v1"
	"google.golang.org/api/chromepolicy/v1"
	"google.golang.org/api/gmail/v1"
	"google.golang.org/api/groupssettings/v1"
	"google.golang.org/api/impersonate"
	"google.golang.org/api/option"
	"google.golang.org/api/transport"
)

type apiClient struct {
	client *http.Client

	AccessToken           string
	ClientScopes          []string
	Credentials           string
	Customer              string
	ImpersonatedUserEmail string
	ServiceAccount        string
	UserAgent             string
}

func (c *apiClient) loadAndValidate(ctx context.Context) diag.Diagnostics {
	var diags diag.Diagnostics

	if len(c.ClientScopes) == 0 {
		c.ClientScopes = DefaultClientScopes
	}

	if c.AccessToken != "" {
		contents, _, err := pathOrContents(c.AccessToken)
		if err != nil {
			return diag.FromErr(err)
		}
		token := &oauth2.Token{AccessToken: contents}

		log.Printf("[INFO] Authenticating using configured Google JSON 'access_token'...")
		log.Printf("[INFO]   -- Scopes: %s", c.ClientScopes)

		if c.ImpersonatedUserEmail != "" {
			if c.ServiceAccount == "" {
				diags = append(diags, diag.Diagnostic{
					Severity: diag.Error,
					Summary:  "service_account is required to impersonate a user with the access_token authentication.",
				})

				return diags
			}

			tokenSource, err := impersonate.CredentialsTokenSource(context.TODO(), impersonate.CredentialsConfig{
				TargetPrincipal: c.ServiceAccount,
				Scopes:          c.ClientScopes,
				Subject:         c.ImpersonatedUserEmail,
			}, option.WithTokenSource(oauth2.StaticTokenSource(token)))
			if err != nil {
				return diag.FromErr(err)
			}

			creds := googleoauth.Credentials{
				TokenSource: tokenSource,
			}
			diags = c.SetupClient(ctx, &creds)
			return diags
		}

		creds := googleoauth.Credentials{
			TokenSource: oauth2.StaticTokenSource(token),
		}
		diags = c.SetupClient(ctx, &creds)
		return diags
	}

	if c.Credentials != "" {
		contents, _, err := pathOrContents(c.Credentials)
		if err != nil {
			return diag.FromErr(err)
		}

		credParams := googleoauth.CredentialsParams{
			Scopes:  c.ClientScopes,
			Subject: c.ImpersonatedUserEmail,
		}

		creds, err := googleoauth.CredentialsFromJSONWithParams(ctx, []byte(contents), credParams)
		if err != nil {
			return diag.FromErr(err)
		}

		diags = c.SetupClient(ctx, creds)
	} else {
		// This assumes we have ADC config
		// Note - this doesn't honor the service account if explicitly set
		creds, opts, err := c.getADCClientConfig(ctx)
		if err != nil {
			return diag.FromErr(err)
		}

		diags = c.SetupClient(ctx, creds, opts...)
	}

	return diags
}

func (c *apiClient) SetupClient(ctx context.Context, creds *googleoauth.Credentials, extraOptions ...option.ClientOption) diag.Diagnostics {
	var diags diag.Diagnostics

	cleanCtx := context.WithValue(ctx, oauth2.HTTPClient, cleanhttp.DefaultClient())

	// Add service options
	opts := []option.ClientOption{
		option.WithTokenSource(creds.TokenSource),
	}
	opts = append(opts, extraOptions...)

	// 1. MTLS TRANSPORT/CLIENT - sets up proper auth headers
	client, _, err := transport.NewHTTPClient(cleanCtx, opts...)
	if err != nil {
		return diag.FromErr(err)
	}

	// 2. Logging Transport - ensure we log HTTP requests to admin APIs.
	scrubbedLoggingTransport := NewTransportWithScrubbedLogs("Google Workspace", client.Transport)

	// 3. Retry Transport - retries common temporary errors
	// Keep order for wrapping logging so we log each retried request as well.
	// This value should be used if needed to create shallow copies with additional retry predicates.
	// See ClientWithAdditionalRetries
	retryTransport := NewTransportWithDefaultRetries(scrubbedLoggingTransport)

	// Set final transport value.
	client.Transport = retryTransport

	c.client = client
	return diags
}

func (c *apiClient) NewChromePolicyService() (*chromepolicy.Service, diag.Diagnostics) {
	var diags diag.Diagnostics

	log.Printf("[INFO] Instantiating Google Admin Chrome Policy service")

	chromePolicyService, err := chromepolicy.NewService(context.Background(), option.WithHTTPClient(c.client))
	if err != nil {
		return nil, diag.FromErr(err)
	}

	if chromePolicyService == nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Directory Service could not be created.",
		})

		return nil, diags
	}

	return chromePolicyService, diags
}

func (c *apiClient) NewDirectoryService() (*directory.Service, diag.Diagnostics) {
	var diags diag.Diagnostics

	log.Printf("[INFO] Instantiating Google Admin Directory service")

	directoryService, err := directory.NewService(context.Background(), option.WithHTTPClient(c.client))
	if err != nil {
		return nil, diag.FromErr(err)
	}

	if directoryService == nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Directory Service could not be created.",
		})

		return nil, diags
	}

	return directoryService, diags
}
func (c *apiClient) NewGmailService(ctx context.Context, userId string) (*gmail.Service, diag.Diagnostics) {
	var diags diag.Diagnostics

	log.Printf("[INFO] Instantiating Google Admin Gmail service")

	// the send-as-alias resource requires the oauth token impersonate the user
	// the alias is being created for.
	log.Printf("[INFO] Creating Google Admin Gmail client that impersonates %q", userId)
	newClient := &apiClient{
		Credentials:           c.Credentials,
		ClientScopes:          c.ClientScopes,
		Customer:              c.Customer,
		UserAgent:             c.UserAgent,
		ImpersonatedUserEmail: userId,
	}
	diags = newClient.loadAndValidate(ctx)
	if diags.HasError() {
		return nil, diags
	}

	gmailService, err := gmail.NewService(ctx, option.WithHTTPClient(newClient.client))
	if err != nil {
		return nil, diag.FromErr(err)
	}

	if gmailService == nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Gmail Service could not be created.",
		})

		return nil, diags
	}

	return gmailService, diags
}

func (c *apiClient) NewGroupsSettingsService() (*groupssettings.Service, diag.Diagnostics) {
	var diags diag.Diagnostics

	log.Printf("[INFO] Instantiating Google Admin Groups Settings service")

	groupsSettingsService, err := groupssettings.NewService(context.Background(), option.WithHTTPClient(c.client))
	if err != nil {
		return nil, diag.FromErr(err)
	}

	if groupsSettingsService == nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Groups Settings Service could not be created.",
		})

		return nil, diags
	}

	return groupsSettingsService, diags
}

func (c *apiClient) serviceAccountFromImpURL(u string) (string, error) {
	const marker = "/serviceAccounts/"
	i := strings.Index(u, marker)
	if i < 0 {
		return "", fmt.Errorf("no serviceAccounts/ in URL")
	}
	rest := u[i+len(marker):]
	j := strings.Index(rest, ":")
	if j < 0 {
		return "", fmt.Errorf("no : in service account segment")
	}
	return rest[:j], nil
}

func (c *apiClient) getADCClientConfig(ctx context.Context) (*googleoauth.Credentials, []option.ClientOption, error) {
	credParams := googleoauth.CredentialsParams{
		Scopes:  c.ClientScopes,
		Subject: c.ImpersonatedUserEmail,
	}

	creds, err := googleoauth.FindDefaultCredentialsWithParams(ctx, credParams)
	if err != nil {
		return nil, nil, err
	}

	// Determine if we need to do more with the type of token we retrieved
	var meta struct {
		Type        string `json:"type"`
		ClientEmail string `json:"client_email"`
		ImpURL      string `json:"service_account_impersonation_url"`
	}
	err = json.Unmarshal(creds.JSON, &meta)
	if err != nil {
		return nil, nil, err
	}
	switch meta.Type {
	case "authorized_user":
		// Mileage will definitely vary - GCP does not like this method
		// In this case, we return a quota project and the creds don't need to be used
		adc_creds, err := credentials.DetectDefault(&credentials.DetectOptions{})
		if err != nil {
			return nil, nil, err
		}
		qp, err := adc_creds.QuotaProjectID(ctx)
		if err != nil {
			return nil, nil, err
		}
		return creds, []option.ClientOption{
			option.WithQuotaProject(qp),
		}, nil
	case "service_account":
		// If we're impersonating an email, then we need to create that impersonation
		if c.ImpersonatedUserEmail != "" {
			ts, err := impersonate.CredentialsTokenSource(ctx, impersonate.CredentialsConfig{
				TargetPrincipal: meta.ClientEmail, // the SA email you set in the action
				Scopes:          c.ClientScopes,
				Subject:         c.ImpersonatedUserEmail, // Workspace user to act as
			}, option.WithTokenSource(creds.TokenSource))
			if err != nil {
				return nil, nil, err
			}

			return &googleoauth.Credentials{TokenSource: ts}, nil, nil
		}
		return creds, nil, nil
	case "impersonated_service_account":
		// If we're impersonating an email, then we need to create that impersonation
		if c.ImpersonatedUserEmail != "" {
			svcAccount, err := c.serviceAccountFromImpURL(meta.ImpURL)
			if err != nil {
				return nil, nil, err
			}

			fmt.Printf("Email is %s", svcAccount)
			ts, err := impersonate.CredentialsTokenSource(ctx, impersonate.CredentialsConfig{
				TargetPrincipal: svcAccount, // the SA email you set in the action
				Scopes:          c.ClientScopes,
				Subject:         c.ImpersonatedUserEmail, // Workspace user to act as
			}, option.WithTokenSource(creds.TokenSource))
			if err != nil {
				return nil, nil, err
			}

			return &googleoauth.Credentials{TokenSource: ts}, nil, nil
		}
		return creds, nil, nil
	case "external_account":
		// External Providers - assumes Workload Identity Federation
		if c.ImpersonatedUserEmail != "" {
			if meta.ImpURL == "" {
				return nil, nil, fmt.Errorf("not sure how to impersonate a user email via external_user adc with no service_account_impersonation_url")
			}

			svcAccount, err := c.serviceAccountFromImpURL(meta.ImpURL)
			if err != nil {
				return nil, nil, err
			}

			ts, err := impersonate.CredentialsTokenSource(ctx, impersonate.CredentialsConfig{
				TargetPrincipal: svcAccount,
				Scopes:          c.ClientScopes,
				Subject:         c.ImpersonatedUserEmail, // Workspace user to act as
			}, option.WithTokenSource(creds.TokenSource))
			if err != nil {
				return nil, nil, err
			}

			return &googleoauth.Credentials{TokenSource: ts}, nil, nil
		}
		return creds, nil, nil
	default:
		return nil, nil, fmt.Errorf("unaccounted for credential type %s", meta.Type)
	}
}
