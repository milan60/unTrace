# unTrace

[![forthebadge](https://forthebadge.com/images/badges/60-percent-of-the-time-works-every-time.svg)](https://forthebadge.com) [![forthebadge](https://forthebadge.com/images/badges/gluten-free.svg)](https://forthebadge.com)

unTrace is a pentester tool. It has built in exploits and useful commands to (for example) cover your traces on a victims system.

## Commands

### `unt help`

Shows a list of commands with their description.

### `unt vanish`

(Tries to) remove all traces of your activity on the target system and then disconnects from it.

### `unt escalate`

Shows a list of priviledge escalation exploits and for which kernel/OS Version they are designed for.

### `unt escalate <exploit>`

Runs the exploit defined in `<exploit>`.

### `unt enum`

Collects important information about the target system in a file called report.txt.

### `unt download`

Downloads a file from the server to the client via scp. This command will ask for the filepath.