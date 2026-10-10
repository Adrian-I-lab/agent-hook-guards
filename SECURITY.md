# Security

## What counts as a security issue here

These guards are coordination for a cooperative but fallible agent, not a security boundary. The README lists known bypasses, such as a script written to disk and then run.

A report is still welcome when:

- a command that a guard claims to block in the README gets through;
- a guard fails open, meaning it allows on bad input, a missing config, a failing tool such as `grep`, or an internal error;
- a guard or its error message prints a secret or a private term it was meant to protect.

## How to report

Please use GitHub private vulnerability reporting on this repository (Security tab, "Report a vulnerability"). The owner has to switch it on in the repository settings, so if the button is missing, open an issue that asks for a private contact and leave out the details. Do not open a public issue for a bypass.

Include the guard, the exact `tool_input` or git command, the config you used (with placeholder paths), and the exit code you saw.
