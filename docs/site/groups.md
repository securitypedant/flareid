# Groups

Groups collect people so you can give them access in one place. Applications receive a person's groups in their sign-in token, and FlareID uses groups for [authentication policies](policies.md), [admin roles](roles.md) and [SCIM](scim.md) scope.

## Static and dynamic groups

| Type | Membership |
|---|---|
| **Static** | People you add by hand, by import, or over SCIM. |
| **Dynamic** | Everyone whose attributes match a rule, such as *department equals Engineering*. Membership updates as attributes change. |

You choose the type when you create the group. A dynamic group can later be **frozen** into a static one with its current members. A static group can't become dynamic.

Groups are flat: a group can't contain another group.

## Create a group

1. Go to **Groups → + New group**.
2. Enter a name and description, and choose **Static** or **Dynamic**.
3. For a dynamic group, add one or more rule conditions. A person must match all of them.
4. For a static group, add members.

## Group managers

Managers can add and remove members and answer membership requests from **My account → Groups**, without any admin console access. Add them on the group's page under **Managers**.

## Access requests and reviews

**Requests.** Tick **People can request membership** on a static group, and people can ask for it from **My account → Groups**. Requests show up in the console under **Groups → Access** and in the notifications bell. Approving one adds the person to the group.

**Reviews.** A review certifies the members of chosen groups. Go to **Groups → Access → New review**, pick the groups, and decide **Keep** or **Revoke** for each membership. Close the review when you're done. Only members added by hand can be reviewed; dynamic members follow their rule.

## Built-in groups

- **Super Admins**: full control of the admin console. Membership is always set by hand.
- **Risk watchlist**: people flagged as risky. Maintained automatically. See [Cloudflare One](cloudflare-one.md#risk-watchlist).

## Bulk actions

On the **Groups** list, select several static groups to turn requests on or off, or add the same people to all of them.
