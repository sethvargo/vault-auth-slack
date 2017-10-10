# Slack Auth Method for Vault

The Vault Auth Slack method is a Vault auth method plugin for authenticating
users via Slack. The plugin can run in multiple different "modes" depending on
your desired user workflow and risk tolerance.

This is both a real custom Vault auth method, and an example of how to build,
install, and maintain your own Vault auth plugin.

## Auth Flow

By default, users must:

- Be a user (not a bot)
- Be an active member of the team (cannot be deleted or suspended)
- Be a member of a configured group, usergroup, or directly mapped
- Be a real member (not guest or multi-channel guest)
- Have two-factor authentication enabled on their Slack account

Some of these values are configurable, others are not. Please see the
configuration and setup section for more details on the configuration options.

## Setup

The setup guide assumes some familiarity with Vault and Vault's plugin
ecosystem. You must have a Vault server already running, unsealed, and
authenticated.

1. Download and decompress the latest plugin binary from the Releases tab on
GitHub. Alternatively you can compile the plugin from source, if you're into
that kinda thing.

1. Move the compiled plugin into Vault's configured `plugin_directory`:

  ```sh
  $ mv vault-auth-slack /etc/vault/plugins/vault-auth-slack
  ```

1. Calculate the SHA256 of the plugin and register it in Vault's plugin catalog.
If you are downloading the pre-compiled binary, it is highly recommended that
you use the published checksums to verify integrity.

  ```sh
  $ export SHA256=$(shasum -a 256 "/etc/vault/plugins/vault-auth-slack" | cut -d' ' -f1)

  $ vault write sys/plugins/catalog/slack-auth-plugin \
      sha_256="${SHA256}" \
      command="vault-auth-slack"
  ```

1. [Create a new application](https://api.slack.com/apps/new) in Slack to your
team:

  - [ ] **AppName**: (anything you want)
  - [ ] **Development Slack Workspace**: the workspace (team) you want to allow
    authentication from

  There are many options and configurable options like colors, logos, etc. You
  can tune these values, but they are not covered in this guide.

  Click on "OAuth and Permissions" in the sidebar.

  - [ ] Add the following scopes to your application:

    - `groups:read`
    - `usergroups:read`

    Be sure to click "Save Changes".

  - [ ] (optional) restrict the list of IP addresses you want to send tokens.

    Be sure to click "Save IP address ranges".

1. Install the application into your team.

  - [ ] Click "Install App" in the sidebar

  - [ ] Click "Install App to Workspace"

  - [ ] Click "Authorize" app

  - [ ] Save the resulting OAuth token securely, temporarily (we will use it to
    configure Vault):

      ```sh
      $ export SLACK_ACCESS_TOKEN="xoxp-2164918114..."
      ```

1. Mount the auth method:

  ```sh
  $ vault auth-enable \
      -path="slack" \
      -plugin-name="slack-auth-plugin plugin"
  ```

1. Configure the auth method using the credentials from the Slack app:

  ```sh
  $ vault write auth/slack/config \
      access_token="${SLACK_ACCESS_TOKEN}" \
      teams="YourTeam"
  ```

  - `access_token` - _(required)_ oauth access token for the Slack application.
    This comes from Slack when you install the application into your team.
    This is used to communicate with Slack's API on your application's behalf.

  - `teams` - _(required)_ comma-separated list of names or IDs of the teams
    (workspaces) for which to allow authentication. Slack is currently in the
    process of renaming "teams" to "workspaces", and it's confusing. We
    apologize. Team names and IDs are case sensitive.

  - `allow_bot_users` - _(default: false)_ allow bots to use their tokens to
    authenticate. By default, bots are not allowed to authenticate.

  - `allow_non_2fa` - _(default: true)_ allow users which do not have 2FA/MFA
    enabled on their Slack account to authenticate. By default, users must have
    2FA enabled on their Slack account to authenticate to Vault. Users must
    still be mapped to an appropriate policy to receive a token.

  - `allow_restricted_users` - _(default: false)_ allow multi-channel guests to
    authenticate. By default, restricted users will not be given a token, even
    if they are mapped to policies.

  - `allow_ultra_restricted_users` - _(default: false)_ allow single-channel
    guests to authenticate. By default, restricted users will not be given a
    token, even if they are mapped to policies.

  - `anyone_policies` - _(default: "")_ comma-separated list of policies to
    apply to everyone. If set, **any Slack member** will be able to authenticate
    to Vault and receive a token with these policies. By default, users must be
    a member of a group, usergroup, or mapped directly.

  Additionally, you can tune the TTLs:

  - `ttl` - minimum TTL for tokens created from this authentication.

  - `max_ttl` - maximum TTL for tokens created from this authentication.

1. Map groups, usergroups, and users:

  > **Security note:** For maximum security, always use IDs instead of human
  names (display names). The auth method supports both for ease of use, but
  many users have privilege to rename groups, usergroups, and users. If you use
  display names instead of IDs, renaming any group, usergroup, or user will
  require updating the configuration to the new name. Using IDs will avoid this
  requirement, since they are persistent for the entity's lifetime.

  - `group` - private channel like `#team-ops`. This is _only_ private channels
    and does not include public channels.

    ```sh
    # Map the "#team-itsec" team to the policy "security"
    $ vault write auth/slack/map/groups/team-itsec policy=security
    ```

    This accepts either a group display name ("team-itsec") or a group ID
    ("G024BE91L"). Group names and IDs are case-sensitive.

  - `usergroup` - group of users name like `@marketing`. These are created and
    managed by Slack admins. Note that `@everyone` and `@channel` are not
    usergroups.

    ```sh
    # Map the "@ops" team to the policies "admin" and "developers"
    $ vault write auth/slack/map/usergroups/ops policy=admin policy=developers
    ```

    This accepts either a usergroup display name ("marketing") or a usergroup ID
    ("S0614TZR7"). Usergroup names and IDs are case sensitive.

    > **Security note:** Slack admins have full control over usergroups, thus
    giving them the ability to add themselves or others to any usergroup. Take
    careful consideration when mapping policies using usergroups.

  - `user` - bot, guest, or member of a team.

    ```sh
    # Map the user "sethvargo" to the policy "root"
    $ vault write auth/slack/map/users/sethvargo policy=root
    ```

    This accepts either a user display name ("sethvargo") or a user ID
    ("W012A3CDE"). User names and IDs are case sensitive.

## Authenticating with a Personal Token

To authenticate, the user generates a personal OAuth token and uses it to
authenticate to Vault. The following considerations should be taken into account
when choosing this auth method:

- This method uses "legacy" tokens, which implies they will be deprecated at
  some point.

- User personal access tokens have a lot of privilege, but this tool only uses
  them for `auth.test` and identity.

### Setup

1. Create a [personal access token][legacy-tokens] for the correct team.

1. Login to Vault with the personal access token:

  ```sh
  $ vault write auth/slack/login token=xoxp-2164918114...
  ```

  The response will be a standard auth response with some token metadata:

  ```text
  Key                                Value
  ---                                -----
  token                              96d250b1-c4b4-2490-9dce-9c2fda6074b1
  token_accessor                     5fd7a9d6-ce3a-10e4-b1cf-f9c3476eea50
  token_duration                     12h0m0s
  token_renewable                    true
  token_policies                     [default ops everyone]
  token_meta_slack_team_id           "T024UT03C"
  token_meta_slack_team_name         "HashiCorp"
  token_meta_slack_user_id           "U02MVRNGK"
  token_meta_slack_user_name         "sethvargo"
  token_meta_slack_user_real_name    "Seth Vargo"
  ```

[legacy-tokens]: https://api.slack.com/custom-integrations/legacy-tokens

## License

This code is licensed under the MIT license, but the Slack API client library is
BSD-licensed.
