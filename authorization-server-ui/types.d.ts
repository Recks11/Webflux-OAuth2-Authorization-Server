export type AuthorizationRequest = {
  client_id: string,
  redirect_uri: string,
  scope: string,
  state: string,
  nonce: string,
  response_type: string,
  grant_type: string
}