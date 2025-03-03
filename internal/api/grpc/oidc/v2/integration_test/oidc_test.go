//go:build integration

package oidc_test

import (
	"context"
	"net/url"
	"regexp"
	"testing"
	"time"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/muhlemmer/gu"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/zitadel/zitadel/internal/integration"
	"github.com/zitadel/zitadel/pkg/grpc/app"
	"github.com/zitadel/zitadel/pkg/grpc/object/v2"
	oidc_pb "github.com/zitadel/zitadel/pkg/grpc/oidc/v2"
	"github.com/zitadel/zitadel/pkg/grpc/session/v2"
)

func TestServer_GetAuthRequest(t *testing.T) {
	project, err := Instance.CreateProject(CTX)
	require.NoError(t, err)
	client, err := Instance.CreateOIDCNativeClient(CTX, redirectURI, logoutRedirectURI, project.GetId(), false)
	require.NoError(t, err)

	tests := []struct {
		name    string
		dep     func() (time.Time, string, error)
		ctx     context.Context
		want    *oidc_pb.GetAuthRequestResponse
		wantErr bool
	}{
		{
			name: "Not found",
			dep: func() (time.Time, string, error) {
				return time.Now(), "123", nil
			},
			ctx:     CTX,
			wantErr: true,
		},
		{
			name: "success",
			dep: func() (time.Time, string, error) {
				return Instance.CreateOIDCAuthRequest(CTX, client.GetClientId(), Instance.Users[integration.UserTypeOrgOwner].ID, redirectURI)
			},
			ctx: CTX,
		},
		{
			name: "without login client, no permission",
			dep: func() (time.Time, string, error) {
				client, err := Instance.CreateOIDCClientLoginVersion(CTX, redirectURI, logoutRedirectURI, project.GetId(), app.OIDCAppType_OIDC_APP_TYPE_NATIVE, app.OIDCAuthMethodType_OIDC_AUTH_METHOD_TYPE_NONE, false, loginV2)
				require.NoError(t, err)
				return Instance.CreateOIDCAuthRequestWithoutLoginClientHeader(CTX, client.GetClientId(), redirectURI, "")
			},
			ctx:     CTX,
			wantErr: true,
		},
		{
			name: "without login client, with permission",
			dep: func() (time.Time, string, error) {
				client, err := Instance.CreateOIDCClientLoginVersion(CTX, redirectURI, logoutRedirectURI, project.GetId(), app.OIDCAppType_OIDC_APP_TYPE_NATIVE, app.OIDCAuthMethodType_OIDC_AUTH_METHOD_TYPE_NONE, false, loginV2)
				require.NoError(t, err)
				return Instance.CreateOIDCAuthRequestWithoutLoginClientHeader(CTX, client.GetClientId(), redirectURI, "")

			},
			ctx: CTXLoginClient,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			now, authRequestID, err := tt.dep()
			require.NoError(t, err)

			got, err := Client.GetAuthRequest(tt.ctx, &oidc_pb.GetAuthRequestRequest{
				AuthRequestId: authRequestID,
			})
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			authRequest := got.GetAuthRequest()
			assert.NotNil(t, authRequest)
			assert.Equal(t, authRequestID, authRequest.GetId())
			assert.WithinRange(t, authRequest.GetCreationDate().AsTime(), now.Add(-time.Second), now.Add(time.Second))
			assert.Contains(t, authRequest.GetScope(), "openid")
		})
	}
}

func TestServer_CreateCallback(t *testing.T) {
	project, err := Instance.CreateProject(CTX)
	require.NoError(t, err)
	client, err := Instance.CreateOIDCNativeClient(CTX, redirectURI, logoutRedirectURI, project.GetId(), false)
	require.NoError(t, err)
	clientV2, err := Instance.CreateOIDCClientLoginVersion(CTX, redirectURI, logoutRedirectURI, project.GetId(), app.OIDCAppType_OIDC_APP_TYPE_NATIVE, app.OIDCAuthMethodType_OIDC_AUTH_METHOD_TYPE_NONE, false, loginV2)
	require.NoError(t, err)
	sessionResp := createSession(t, CTX, Instance.Users[integration.UserTypeOrgOwner].ID)

	tests := []struct {
		name      string
		ctx       context.Context
		req       *oidc_pb.CreateCallbackRequest
		AuthError string
		want      *oidc_pb.CreateCallbackResponse
		wantURL   *url.URL
		wantErr   bool
	}{
		{
			name: "Not found",
			ctx:  CTX,
			req: &oidc_pb.CreateCallbackRequest{
				AuthRequestId: "123",
				CallbackKind: &oidc_pb.CreateCallbackRequest_Session{
					Session: &oidc_pb.Session{
						SessionId:    sessionResp.GetSessionId(),
						SessionToken: sessionResp.GetSessionToken(),
					},
				},
			},
			wantErr: true,
		},
		{
			name: "session not found",
			ctx:  CTX,
			req: &oidc_pb.CreateCallbackRequest{
				AuthRequestId: func() string {
					_, authRequestID, err := Instance.CreateOIDCAuthRequest(CTX, client.GetClientId(), Instance.Users[integration.UserTypeOrgOwner].ID, redirectURI)
					require.NoError(t, err)
					return authRequestID
				}(),
				CallbackKind: &oidc_pb.CreateCallbackRequest_Session{
					Session: &oidc_pb.Session{
						SessionId:    "foo",
						SessionToken: "bar",
					},
				},
			},
			wantErr: true,
		},
		{
			name: "session token invalid",
			ctx:  CTX,
			req: &oidc_pb.CreateCallbackRequest{
				AuthRequestId: func() string {
					_, authRequestID, err := Instance.CreateOIDCAuthRequest(CTX, client.GetClientId(), Instance.Users.Get(integration.UserTypeOrgOwner).ID, redirectURI)
					require.NoError(t, err)
					return authRequestID
				}(),
				CallbackKind: &oidc_pb.CreateCallbackRequest_Session{
					Session: &oidc_pb.Session{
						SessionId:    sessionResp.GetSessionId(),
						SessionToken: "bar",
					},
				},
			},
			wantErr: true,
		},
		{
			name: "fail callback",
			ctx:  CTX,
			req: &oidc_pb.CreateCallbackRequest{
				AuthRequestId: func() string {
					_, authRequestID, err := Instance.CreateOIDCAuthRequest(CTX, client.GetClientId(), Instance.Users.Get(integration.UserTypeOrgOwner).ID, redirectURI)
					require.NoError(t, err)
					return authRequestID
				}(),
				CallbackKind: &oidc_pb.CreateCallbackRequest_Error{
					Error: &oidc_pb.AuthorizationError{
						Error:            oidc_pb.ErrorReason_ERROR_REASON_ACCESS_DENIED,
						ErrorDescription: gu.Ptr("nope"),
						ErrorUri:         gu.Ptr("https://example.com/docs"),
					},
				},
			},
			want: &oidc_pb.CreateCallbackResponse{
				CallbackUrl: regexp.QuoteMeta(`oidcintegrationtest://callback?error=access_denied&error_description=nope&error_uri=https%3A%2F%2Fexample.com%2Fdocs&state=state`),
				Details: &object.Details{
					ChangeDate:    timestamppb.Now(),
					ResourceOwner: Instance.ID(),
				},
			},
			wantErr: false,
		},
		{
			name: "fail callback, no login client header",
			ctx:  CTXLoginClient,
			req: &oidc_pb.CreateCallbackRequest{
				AuthRequestId: func() string {
					_, authRequestID, err := Instance.CreateOIDCAuthRequestWithoutLoginClientHeader(CTX, clientV2.GetClientId(), redirectURI, "")
					require.NoError(t, err)
					return authRequestID
				}(),
				CallbackKind: &oidc_pb.CreateCallbackRequest_Error{
					Error: &oidc_pb.AuthorizationError{
						Error:            oidc_pb.ErrorReason_ERROR_REASON_ACCESS_DENIED,
						ErrorDescription: gu.Ptr("nope"),
						ErrorUri:         gu.Ptr("https://example.com/docs"),
					},
				},
			},
			want: &oidc_pb.CreateCallbackResponse{
				CallbackUrl: regexp.QuoteMeta(`oidcintegrationtest://callback?error=access_denied&error_description=nope&error_uri=https%3A%2F%2Fexample.com%2Fdocs&state=state`),
				Details: &object.Details{
					ChangeDate:    timestamppb.Now(),
					ResourceOwner: Instance.ID(),
				},
			},
			wantErr: false,
		},
		{
			name: "code callback",
			ctx:  CTX,
			req: &oidc_pb.CreateCallbackRequest{
				AuthRequestId: func() string {
					_, authRequestID, err := Instance.CreateOIDCAuthRequest(CTX, client.GetClientId(), Instance.Users.Get(integration.UserTypeOrgOwner).ID, redirectURI)
					require.NoError(t, err)
					return authRequestID
				}(),
				CallbackKind: &oidc_pb.CreateCallbackRequest_Session{
					Session: &oidc_pb.Session{
						SessionId:    sessionResp.GetSessionId(),
						SessionToken: sessionResp.GetSessionToken(),
					},
				},
			},
			want: &oidc_pb.CreateCallbackResponse{
				CallbackUrl: `oidcintegrationtest:\/\/callback\?code=(.*)&state=state`,
				Details: &object.Details{
					ChangeDate:    timestamppb.Now(),
					ResourceOwner: Instance.ID(),
				},
			},
			wantErr: false,
		},
		{
			name: "code callback, no login client header, no permission, error",
			ctx:  CTX,
			req: &oidc_pb.CreateCallbackRequest{
				AuthRequestId: func() string {
					_, authRequestID, err := Instance.CreateOIDCAuthRequestWithoutLoginClientHeader(CTX, clientV2.GetClientId(), redirectURI, "")
					require.NoError(t, err)
					return authRequestID
				}(),
				CallbackKind: &oidc_pb.CreateCallbackRequest_Session{
					Session: &oidc_pb.Session{
						SessionId:    sessionResp.GetSessionId(),
						SessionToken: sessionResp.GetSessionToken(),
					},
				},
			},
			wantErr: true,
		},
		{
			name: "code callback, no login client header, with permission",
			ctx:  CTXLoginClient,
			req: &oidc_pb.CreateCallbackRequest{
				AuthRequestId: func() string {
					_, authRequestID, err := Instance.CreateOIDCAuthRequestWithoutLoginClientHeader(CTX, clientV2.GetClientId(), redirectURI, "")
					require.NoError(t, err)
					return authRequestID
				}(),
				CallbackKind: &oidc_pb.CreateCallbackRequest_Session{
					Session: &oidc_pb.Session{
						SessionId:    sessionResp.GetSessionId(),
						SessionToken: sessionResp.GetSessionToken(),
					},
				},
			},
			want: &oidc_pb.CreateCallbackResponse{
				CallbackUrl: `oidcintegrationtest:\/\/callback\?code=(.*)&state=state`,
				Details: &object.Details{
					ChangeDate:    timestamppb.Now(),
					ResourceOwner: Instance.ID(),
				},
			},
			wantErr: false,
		},
		{
			name: "implicit",
			ctx:  CTX,
			req: &oidc_pb.CreateCallbackRequest{
				AuthRequestId: func() string {
					client, err := Instance.CreateOIDCImplicitFlowClient(CTX, redirectURIImplicit, nil)
					require.NoError(t, err)
					authRequestID, err := Instance.CreateOIDCAuthRequestImplicit(CTX, client.GetClientId(), Instance.Users.Get(integration.UserTypeOrgOwner).ID, redirectURIImplicit)
					require.NoError(t, err)
					return authRequestID
				}(),
				CallbackKind: &oidc_pb.CreateCallbackRequest_Session{
					Session: &oidc_pb.Session{
						SessionId:    sessionResp.GetSessionId(),
						SessionToken: sessionResp.GetSessionToken(),
					},
				},
			},
			want: &oidc_pb.CreateCallbackResponse{
				CallbackUrl: `http:\/\/localhost:9999\/callback#access_token=(.*)&expires_in=(.*)&id_token=(.*)&state=state&token_type=Bearer`,
				Details: &object.Details{
					ChangeDate:    timestamppb.Now(),
					ResourceOwner: Instance.ID(),
				},
			},
			wantErr: false,
		},
		{
			name: "implicit, no login client header",
			ctx:  CTXLoginClient,
			req: &oidc_pb.CreateCallbackRequest{
				AuthRequestId: func() string {
					clientV2, err := Instance.CreateOIDCImplicitFlowClient(CTX, redirectURIImplicit, loginV2)
					require.NoError(t, err)
					authRequestID, err := Instance.CreateOIDCAuthRequestImplicitWithoutLoginClientHeader(CTX, clientV2.GetClientId(), redirectURIImplicit)
					require.NoError(t, err)
					return authRequestID
				}(),
				CallbackKind: &oidc_pb.CreateCallbackRequest_Session{
					Session: &oidc_pb.Session{
						SessionId:    sessionResp.GetSessionId(),
						SessionToken: sessionResp.GetSessionToken(),
					},
				},
			},
			want: &oidc_pb.CreateCallbackResponse{
				CallbackUrl: `http:\/\/localhost:9999\/callback#access_token=(.*)&expires_in=(.*)&id_token=(.*)&state=state&token_type=Bearer`,
				Details: &object.Details{
					ChangeDate:    timestamppb.Now(),
					ResourceOwner: Instance.ID(),
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Client.CreateCallback(tt.ctx, tt.req)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			integration.AssertDetails(t, tt.want, got)
			if tt.want != nil {
				assert.Regexp(t, regexp.MustCompile(tt.want.CallbackUrl), got.GetCallbackUrl())
			}
		})
	}
}

func TestServer_CreateCallback_Permission(t *testing.T) {
	tests := []struct {
		name    string
		ctx     context.Context
		dep     func(ctx context.Context, t *testing.T) *oidc_pb.CreateCallbackRequest
		want    *oidc_pb.CreateCallbackResponse
		wantURL *url.URL
		wantErr bool
	}{
		{
			name: "usergrant to project and different resourceowner with different project grant",
			ctx:  CTX,
			dep: func(ctx context.Context, t *testing.T) *oidc_pb.CreateCallbackRequest {
				projectID, clientID := createOIDCApplication(ctx, t, true, true)
				projectID2, _ := createOIDCApplication(ctx, t, true, true)

				orgResp := Instance.CreateOrganization(ctx, "oidc-permission-"+gofakeit.AppName(), gofakeit.Email())
				Instance.CreateProjectGrant(ctx, projectID2, orgResp.GetOrganizationId())
				user := Instance.CreateHumanUserVerified(ctx, orgResp.GetOrganizationId(), gofakeit.Email(), gofakeit.Phone())
				Instance.CreateProjectUserGrant(t, ctx, projectID, user.GetUserId())

				return createSessionAndAuthRequestForCallback(ctx, t, clientID, Instance.Users.Get(integration.UserTypeOrgOwner).ID, user.GetUserId())
			},
			wantErr: true,
		},
		{
			name: "usergrant to project and different resourceowner with project grant",
			ctx:  CTX,
			dep: func(ctx context.Context, t *testing.T) *oidc_pb.CreateCallbackRequest {
				projectID, clientID := createOIDCApplication(ctx, t, true, true)

				orgResp := Instance.CreateOrganization(ctx, "oidc-permission-"+gofakeit.AppName(), gofakeit.Email())
				Instance.CreateProjectGrant(ctx, projectID, orgResp.GetOrganizationId())
				user := Instance.CreateHumanUserVerified(ctx, orgResp.GetOrganizationId(), gofakeit.Email(), gofakeit.Phone())
				Instance.CreateProjectUserGrant(t, ctx, projectID, user.GetUserId())

				return createSessionAndAuthRequestForCallback(ctx, t, clientID, Instance.Users.Get(integration.UserTypeOrgOwner).ID, user.GetUserId())
			},
			want: &oidc_pb.CreateCallbackResponse{
				CallbackUrl: `oidcintegrationtest:\/\/callback\?code=(.*)&state=state`,
				Details: &object.Details{
					ChangeDate:    timestamppb.Now(),
					ResourceOwner: Instance.ID(),
				},
			},
		},
		{
			name: "usergrant to project grant and different resourceowner with project grant",
			ctx:  CTX,
			dep: func(ctx context.Context, t *testing.T) *oidc_pb.CreateCallbackRequest {
				projectID, clientID := createOIDCApplication(ctx, t, true, true)

				orgResp := Instance.CreateOrganization(ctx, "oidc-permission-"+gofakeit.AppName(), gofakeit.Email())
				projectGrantResp := Instance.CreateProjectGrant(ctx, projectID, orgResp.GetOrganizationId())
				user := Instance.CreateHumanUserVerified(ctx, orgResp.GetOrganizationId(), gofakeit.Email(), gofakeit.Phone())
				Instance.CreateProjectGrantUserGrant(ctx, orgResp.GetOrganizationId(), projectID, projectGrantResp.GetGrantId(), user.GetUserId())

				return createSessionAndAuthRequestForCallback(ctx, t, clientID, Instance.Users.Get(integration.UserTypeOrgOwner).ID, user.GetUserId())
			},
			want: &oidc_pb.CreateCallbackResponse{
				CallbackUrl: `oidcintegrationtest:\/\/callback\?code=(.*)&state=state`,
				Details: &object.Details{
					ChangeDate:    timestamppb.Now(),
					ResourceOwner: Instance.ID(),
				},
			},
		},
		{
			name: "no usergrant and different resourceowner",
			ctx:  CTX,
			dep: func(ctx context.Context, t *testing.T) *oidc_pb.CreateCallbackRequest {
				_, clientID := createOIDCApplication(ctx, t, true, true)

				orgResp := Instance.CreateOrganization(ctx, "oidc-permission-"+gofakeit.AppName(), gofakeit.Email())
				user := Instance.CreateHumanUserVerified(ctx, orgResp.GetOrganizationId(), gofakeit.Email(), gofakeit.Phone())

				return createSessionAndAuthRequestForCallback(ctx, t, clientID, Instance.Users.Get(integration.UserTypeOrgOwner).ID, user.GetUserId())
			},
			wantErr: true,
		},
		{
			name: "no usergrant and same resourceowner",
			ctx:  CTX,
			dep: func(ctx context.Context, t *testing.T) *oidc_pb.CreateCallbackRequest {
				_, clientID := createOIDCApplication(ctx, t, true, true)
				user := Instance.CreateHumanUser(ctx)

				return createSessionAndAuthRequestForCallback(ctx, t, clientID, Instance.Users.Get(integration.UserTypeOrgOwner).ID, user.GetUserId())
			},
			wantErr: true,
		},
		{
			name: "usergrant and different resourceowner",
			ctx:  CTX,
			dep: func(ctx context.Context, t *testing.T) *oidc_pb.CreateCallbackRequest {
				projectID, clientID := createOIDCApplication(ctx, t, true, true)

				orgResp := Instance.CreateOrganization(ctx, "oidc-permission-"+gofakeit.AppName(), gofakeit.Email())
				user := Instance.CreateHumanUserVerified(ctx, orgResp.GetOrganizationId(), gofakeit.Email(), gofakeit.Phone())
				Instance.CreateProjectUserGrant(t, ctx, projectID, user.GetUserId())

				return createSessionAndAuthRequestForCallback(ctx, t, clientID, Instance.Users.Get(integration.UserTypeOrgOwner).ID, user.GetUserId())
			},
			wantErr: true,
		},
		{
			name: "usergrant and same resourceowner",
			ctx:  CTX,
			dep: func(ctx context.Context, t *testing.T) *oidc_pb.CreateCallbackRequest {
				projectID, clientID := createOIDCApplication(ctx, t, true, true)
				user := Instance.CreateHumanUser(ctx)
				Instance.CreateProjectUserGrant(t, ctx, projectID, user.GetUserId())

				return createSessionAndAuthRequestForCallback(ctx, t, clientID, Instance.Users.Get(integration.UserTypeOrgOwner).ID, user.GetUserId())
			},
			want: &oidc_pb.CreateCallbackResponse{
				CallbackUrl: `oidcintegrationtest:\/\/callback\?code=(.*)&state=state`,
				Details: &object.Details{
					ChangeDate:    timestamppb.Now(),
					ResourceOwner: Instance.ID(),
				},
			},
		},
		{
			name: "projectRoleCheck, usergrant and same resourceowner",
			ctx:  CTX,
			dep: func(ctx context.Context, t *testing.T) *oidc_pb.CreateCallbackRequest {
				projectID, clientID := createOIDCApplication(ctx, t, true, false)
				user := Instance.CreateHumanUser(ctx)
				Instance.CreateProjectUserGrant(t, ctx, projectID, user.GetUserId())

				return createSessionAndAuthRequestForCallback(ctx, t, clientID, Instance.Users.Get(integration.UserTypeOrgOwner).ID, user.GetUserId())
			},
			want: &oidc_pb.CreateCallbackResponse{
				CallbackUrl: `oidcintegrationtest:\/\/callback\?code=(.*)&state=state`,
				Details: &object.Details{
					ChangeDate:    timestamppb.Now(),
					ResourceOwner: Instance.ID(),
				},
			},
		},
		{
			name: "projectRoleCheck, no usergrant and same resourceowner",
			ctx:  CTX,
			dep: func(ctx context.Context, t *testing.T) *oidc_pb.CreateCallbackRequest {
				_, clientID := createOIDCApplication(ctx, t, true, false)
				user := Instance.CreateHumanUser(ctx)

				return createSessionAndAuthRequestForCallback(ctx, t, clientID, Instance.Users.Get(integration.UserTypeOrgOwner).ID, user.GetUserId())
			},
			wantErr: true,
		},
		{
			name: "projectRoleCheck, usergrant and different resourceowner",
			ctx:  CTX,
			dep: func(ctx context.Context, t *testing.T) *oidc_pb.CreateCallbackRequest {
				projectID, clientID := createOIDCApplication(ctx, t, true, false)
				orgResp := Instance.CreateOrganization(ctx, "oidc-permission-"+gofakeit.AppName(), gofakeit.Email())
				user := Instance.CreateHumanUserVerified(ctx, orgResp.GetOrganizationId(), gofakeit.Email(), gofakeit.Phone())
				Instance.CreateProjectUserGrant(t, ctx, projectID, user.GetUserId())

				return createSessionAndAuthRequestForCallback(ctx, t, clientID, Instance.Users.Get(integration.UserTypeOrgOwner).ID, user.GetUserId())
			},
			want: &oidc_pb.CreateCallbackResponse{
				CallbackUrl: `oidcintegrationtest:\/\/callback\?code=(.*)&state=state`,
				Details: &object.Details{
					ChangeDate:    timestamppb.Now(),
					ResourceOwner: Instance.ID(),
				},
			},
		},
		{
			name: "projectRoleCheck, no usergrant and different resourceowner",
			ctx:  CTX,
			dep: func(ctx context.Context, t *testing.T) *oidc_pb.CreateCallbackRequest {
				_, clientID := createOIDCApplication(ctx, t, true, false)
				orgResp := Instance.CreateOrganization(ctx, "oidc-permission-"+gofakeit.AppName(), gofakeit.Email())
				user := Instance.CreateHumanUserVerified(ctx, orgResp.GetOrganizationId(), gofakeit.Email(), gofakeit.Phone())

				return createSessionAndAuthRequestForCallback(ctx, t, clientID, Instance.Users.Get(integration.UserTypeOrgOwner).ID, user.GetUserId())
			},
			wantErr: true,
		},
		{
			name: "projectRoleCheck, usergrant on project grant and different resourceowner",
			ctx:  CTX,
			dep: func(ctx context.Context, t *testing.T) *oidc_pb.CreateCallbackRequest {
				projectID, clientID := createOIDCApplication(ctx, t, true, false)

				orgResp := Instance.CreateOrganization(ctx, "oidc-permission-"+gofakeit.AppName(), gofakeit.Email())
				projectGrantResp := Instance.CreateProjectGrant(ctx, projectID, orgResp.GetOrganizationId())
				user := Instance.CreateHumanUserVerified(ctx, orgResp.GetOrganizationId(), gofakeit.Email(), gofakeit.Phone())
				Instance.CreateProjectGrantUserGrant(ctx, orgResp.GetOrganizationId(), projectID, projectGrantResp.GetGrantId(), user.GetUserId())
				return createSessionAndAuthRequestForCallback(ctx, t, clientID, Instance.Users.Get(integration.UserTypeOrgOwner).ID, user.GetUserId())
			},
			want: &oidc_pb.CreateCallbackResponse{
				CallbackUrl: `oidcintegrationtest:\/\/callback\?code=(.*)&state=state`,
				Details: &object.Details{
					ChangeDate:    timestamppb.Now(),
					ResourceOwner: Instance.ID(),
				},
			},
		},
		{
			name: "projectRoleCheck, no usergrant on project grant and different resourceowner",
			ctx:  CTX,
			dep: func(ctx context.Context, t *testing.T) *oidc_pb.CreateCallbackRequest {
				projectID, clientID := createOIDCApplication(ctx, t, true, false)

				orgResp := Instance.CreateOrganization(ctx, "oidc-permission-"+gofakeit.AppName(), gofakeit.Email())
				Instance.CreateProjectGrant(ctx, projectID, orgResp.GetOrganizationId())
				user := Instance.CreateHumanUserVerified(ctx, orgResp.GetOrganizationId(), gofakeit.Email(), gofakeit.Phone())
				return createSessionAndAuthRequestForCallback(ctx, t, clientID, Instance.Users.Get(integration.UserTypeOrgOwner).ID, user.GetUserId())
			},
			wantErr: true,
		},
		{
			name: "hasProjectCheck, same resourceowner",
			ctx:  CTX,
			dep: func(ctx context.Context, t *testing.T) *oidc_pb.CreateCallbackRequest {
				user := Instance.CreateHumanUser(ctx)
				_, clientID := createOIDCApplication(ctx, t, false, true)

				return createSessionAndAuthRequestForCallback(ctx, t, clientID, Instance.Users.Get(integration.UserTypeOrgOwner).ID, user.GetUserId())
			},
			want: &oidc_pb.CreateCallbackResponse{
				CallbackUrl: `oidcintegrationtest:\/\/callback\?code=(.*)&state=state`,
				Details: &object.Details{
					ChangeDate:    timestamppb.Now(),
					ResourceOwner: Instance.ID(),
				},
			},
		},
		{
			name: "hasProjectCheck, different resourceowner",
			ctx:  CTX,
			dep: func(ctx context.Context, t *testing.T) *oidc_pb.CreateCallbackRequest {
				_, clientID := createOIDCApplication(ctx, t, false, true)
				orgResp := Instance.CreateOrganization(ctx, "oidc-permission-"+gofakeit.AppName(), gofakeit.Email())
				user := Instance.CreateHumanUserVerified(ctx, orgResp.GetOrganizationId(), gofakeit.Email(), gofakeit.Phone())

				return createSessionAndAuthRequestForCallback(ctx, t, clientID, Instance.Users.Get(integration.UserTypeOrgOwner).ID, user.GetUserId())
			},
			wantErr: true,
		},
		{
			name: "hasProjectCheck, different resourceowner with project grant",
			ctx:  CTX,
			dep: func(ctx context.Context, t *testing.T) *oidc_pb.CreateCallbackRequest {
				projectID, clientID := createOIDCApplication(ctx, t, false, true)

				orgResp := Instance.CreateOrganization(ctx, "oidc-permission-"+gofakeit.AppName(), gofakeit.Email())
				Instance.CreateProjectGrant(ctx, projectID, orgResp.GetOrganizationId())
				user := Instance.CreateHumanUserVerified(ctx, orgResp.GetOrganizationId(), gofakeit.Email(), gofakeit.Phone())

				return createSessionAndAuthRequestForCallback(ctx, t, clientID, Instance.Users.Get(integration.UserTypeOrgOwner).ID, user.GetUserId())
			},
			want: &oidc_pb.CreateCallbackResponse{
				CallbackUrl: `oidcintegrationtest:\/\/callback\?code=(.*)&state=state`,
				Details: &object.Details{
					ChangeDate:    timestamppb.Now(),
					ResourceOwner: Instance.ID(),
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := tt.dep(IAMCTX, t)

			got, err := Client.CreateCallback(tt.ctx, req)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			integration.AssertDetails(t, tt.want, got)
			if tt.want != nil {
				assert.Regexp(t, regexp.MustCompile(tt.want.CallbackUrl), got.GetCallbackUrl())
			}
		})
	}
}

func TestServer_GetDeviceAuthorizationRequest(t *testing.T) {
	project, err := Instance.CreateProject(CTX)
	require.NoError(t, err)
	client, err := Instance.CreateOIDCClient(CTX, redirectURI, logoutRedirectURI, project.GetId(), app.OIDCAppType_OIDC_APP_TYPE_NATIVE, app.OIDCAuthMethodType_OIDC_AUTH_METHOD_TYPE_NONE, false, app.OIDCGrantType_OIDC_GRANT_TYPE_DEVICE_CODE)
	require.NoError(t, err)

	tests := []struct {
		name    string
		dep     func() (*oidc.DeviceAuthorizationResponse, error)
		ctx     context.Context
		want    *oidc.DeviceAuthorizationResponse
		wantErr bool
	}{
		{
			name: "Not found",
			dep: func() (*oidc.DeviceAuthorizationResponse, error) {
				return &oidc.DeviceAuthorizationResponse{
					UserCode: "notFound",
				}, nil
			},
			ctx:     CTX,
			wantErr: true,
		},
		{
			name: "success",
			dep: func() (*oidc.DeviceAuthorizationResponse, error) {
				return Instance.CreateDeviceAuthorizationRequest(CTX, client.GetClientId(), "openid")
			},
			ctx: CTX,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			deviceAuth, err := tt.dep()
			require.NoError(t, err)

			got, err := Client.GetDeviceAuthorizationRequest(tt.ctx, &oidc_pb.GetDeviceAuthorizationRequestRequest{
				UserCode: deviceAuth.UserCode,
			})
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			authRequest := got.GetDeviceAuthorizationRequest()
			assert.NotNil(t, authRequest)
			assert.NotEmpty(t, authRequest.GetId())
			assert.Equal(t, client.GetClientId(), authRequest.GetClientId())
			assert.Contains(t, authRequest.GetScope(), "openid")
			assert.NotEmpty(t, authRequest.GetAppName())
			assert.NotEmpty(t, authRequest.GetProjectName())
		})
	}
}

func TestServer_AuthorizeOrDenyDeviceAuthorization(t *testing.T) {
	project, err := Instance.CreateProject(CTX)
	require.NoError(t, err)
	client, err := Instance.CreateOIDCClient(CTX, redirectURI, logoutRedirectURI, project.GetId(), app.OIDCAppType_OIDC_APP_TYPE_NATIVE, app.OIDCAuthMethodType_OIDC_AUTH_METHOD_TYPE_NONE, false, app.OIDCGrantType_OIDC_GRANT_TYPE_DEVICE_CODE)
	require.NoError(t, err)
	sessionResp := createSession(t, CTX, Instance.Users[integration.UserTypeOrgOwner].ID)

	tests := []struct {
		name      string
		ctx       context.Context
		req       *oidc_pb.AuthorizeOrDenyDeviceAuthorizationRequest
		AuthError string
		want      *oidc_pb.AuthorizeOrDenyDeviceAuthorizationResponse
		wantURL   *url.URL
		wantErr   bool
	}{
		{
			name: "Not found",
			ctx:  CTX,
			req: &oidc_pb.AuthorizeOrDenyDeviceAuthorizationRequest{
				DeviceAuthorizationId: "123",
				Decision: &oidc_pb.AuthorizeOrDenyDeviceAuthorizationRequest_Session{
					Session: &oidc_pb.Session{
						SessionId:    sessionResp.GetSessionId(),
						SessionToken: sessionResp.GetSessionToken(),
					},
				},
			},
			wantErr: true,
		},
		{
			name: "session not found",
			ctx:  CTX,
			req: &oidc_pb.AuthorizeOrDenyDeviceAuthorizationRequest{
				DeviceAuthorizationId: func() string {
					req, err := Instance.CreateDeviceAuthorizationRequest(CTX, client.GetClientId(), "openid")
					require.NoError(t, err)
					var id string
					assert.EventuallyWithT(t, func(collectT *assert.CollectT) {
						resp, err := Instance.Client.OIDCv2.GetDeviceAuthorizationRequest(CTX, &oidc_pb.GetDeviceAuthorizationRequestRequest{
							UserCode: req.UserCode,
						})
						assert.NoError(t, err)
						id = resp.GetDeviceAuthorizationRequest().GetId()
					}, 5*time.Second, 100*time.Millisecond)
					return id
				}(),
				Decision: &oidc_pb.AuthorizeOrDenyDeviceAuthorizationRequest_Session{
					Session: &oidc_pb.Session{
						SessionId:    "foo",
						SessionToken: "bar",
					},
				},
			},
			wantErr: true,
		},
		{
			name: "session token invalid",
			ctx:  CTX,
			req: &oidc_pb.AuthorizeOrDenyDeviceAuthorizationRequest{
				DeviceAuthorizationId: func() string {
					req, err := Instance.CreateDeviceAuthorizationRequest(CTX, client.GetClientId(), "openid")
					require.NoError(t, err)
					var id string
					assert.EventuallyWithT(t, func(collectT *assert.CollectT) {
						resp, err := Instance.Client.OIDCv2.GetDeviceAuthorizationRequest(CTX, &oidc_pb.GetDeviceAuthorizationRequestRequest{
							UserCode: req.UserCode,
						})
						assert.NoError(collectT, err)
						id = resp.GetDeviceAuthorizationRequest().GetId()
					}, 5*time.Second, 100*time.Millisecond)
					return id
				}(),
				Decision: &oidc_pb.AuthorizeOrDenyDeviceAuthorizationRequest_Session{
					Session: &oidc_pb.Session{
						SessionId:    sessionResp.GetSessionId(),
						SessionToken: "bar",
					},
				},
			},
			wantErr: true,
		},
		{
			name: "deny device authorization",
			ctx:  CTX,
			req: &oidc_pb.AuthorizeOrDenyDeviceAuthorizationRequest{
				DeviceAuthorizationId: func() string {
					req, err := Instance.CreateDeviceAuthorizationRequest(CTX, client.GetClientId(), "openid")
					require.NoError(t, err)
					var id string
					assert.EventuallyWithT(t, func(collectT *assert.CollectT) {
						resp, err := Instance.Client.OIDCv2.GetDeviceAuthorizationRequest(CTX, &oidc_pb.GetDeviceAuthorizationRequestRequest{
							UserCode: req.UserCode,
						})
						assert.NoError(collectT, err)
						id = resp.GetDeviceAuthorizationRequest().GetId()
					}, 5*time.Second, 100*time.Millisecond)
					return id
				}(),
				Decision: &oidc_pb.AuthorizeOrDenyDeviceAuthorizationRequest_Deny{},
			},
			want:    &oidc_pb.AuthorizeOrDenyDeviceAuthorizationResponse{},
			wantErr: false,
		},
		{
			name: "authorize, no permission, error",
			ctx:  CTX,
			req: &oidc_pb.AuthorizeOrDenyDeviceAuthorizationRequest{
				DeviceAuthorizationId: func() string {
					req, err := Instance.CreateDeviceAuthorizationRequest(CTX, client.GetClientId(), "openid")
					require.NoError(t, err)
					var id string
					assert.EventuallyWithT(t, func(collectT *assert.CollectT) {
						resp, err := Instance.Client.OIDCv2.GetDeviceAuthorizationRequest(CTX, &oidc_pb.GetDeviceAuthorizationRequestRequest{
							UserCode: req.UserCode,
						})
						assert.NoError(collectT, err)
						id = resp.GetDeviceAuthorizationRequest().GetId()
					}, 5*time.Second, 100*time.Millisecond)
					return id
				}(),
				Decision: &oidc_pb.AuthorizeOrDenyDeviceAuthorizationRequest_Session{
					Session: &oidc_pb.Session{
						SessionId:    sessionResp.GetSessionId(),
						SessionToken: sessionResp.GetSessionToken(),
					},
				},
			},
			wantErr: true,
		},
		{
			name: "authorize, with permission",
			ctx:  CTXLoginClient,
			req: &oidc_pb.AuthorizeOrDenyDeviceAuthorizationRequest{
				DeviceAuthorizationId: func() string {
					req, err := Instance.CreateDeviceAuthorizationRequest(CTX, client.GetClientId(), "openid")
					require.NoError(t, err)
					var id string
					assert.EventuallyWithT(t, func(collectT *assert.CollectT) {
						resp, err := Instance.Client.OIDCv2.GetDeviceAuthorizationRequest(CTX, &oidc_pb.GetDeviceAuthorizationRequestRequest{
							UserCode: req.UserCode,
						})
						assert.NoError(collectT, err)
						id = resp.GetDeviceAuthorizationRequest().GetId()
					}, 5*time.Second, 100*time.Millisecond)
					return id
				}(),
				Decision: &oidc_pb.AuthorizeOrDenyDeviceAuthorizationRequest_Session{
					Session: &oidc_pb.Session{
						SessionId:    sessionResp.GetSessionId(),
						SessionToken: sessionResp.GetSessionToken(),
					},
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Client.AuthorizeOrDenyDeviceAuthorization(tt.ctx, tt.req)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

func createSession(t *testing.T, ctx context.Context, userID string) *session.CreateSessionResponse {
	sessionResp, err := Instance.Client.SessionV2.CreateSession(ctx, &session.CreateSessionRequest{
		Checks: &session.Checks{
			User: &session.CheckUser{
				Search: &session.CheckUser_UserId{
					UserId: userID,
				},
			},
		},
	})
	require.NoError(t, err)
	return sessionResp
}

func createSessionAndAuthRequestForCallback(ctx context.Context, t *testing.T, clientID, loginClient, userID string) *oidc_pb.CreateCallbackRequest {
	_, authRequestID, err := Instance.CreateOIDCAuthRequest(ctx, clientID, loginClient, redirectURI)
	require.NoError(t, err)
	sessionResp := createSession(t, ctx, userID)
	return &oidc_pb.CreateCallbackRequest{
		AuthRequestId: authRequestID,
		CallbackKind: &oidc_pb.CreateCallbackRequest_Session{
			Session: &oidc_pb.Session{
				SessionId:    sessionResp.GetSessionId(),
				SessionToken: sessionResp.GetSessionToken(),
			},
		},
	}
}

func createOIDCApplication(ctx context.Context, t *testing.T, projectRoleCheck, hasProjectCheck bool) (string, string) {
	project, err := Instance.CreateProjectWithPermissionCheck(ctx, projectRoleCheck, hasProjectCheck)
	require.NoError(t, err)
	clientV2, err := Instance.CreateOIDCClientLoginVersion(ctx, redirectURI, logoutRedirectURI, project.GetId(), app.OIDCAppType_OIDC_APP_TYPE_NATIVE, app.OIDCAuthMethodType_OIDC_AUTH_METHOD_TYPE_NONE, false, loginV2)
	require.NoError(t, err)
	return project.GetId(), clientV2.GetClientId()
}
