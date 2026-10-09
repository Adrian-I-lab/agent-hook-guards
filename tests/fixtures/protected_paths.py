"""Fixture for the protected-paths case file.

Builds, inside a fresh temporary directory ROOT:

    ROOT/protected-share/           the protected area (a stand-in for a mount)
    ROOT/protected-share/secret.txt
    ROOT/protected-share/sub/deep.txt
    ROOT/work/                      the working directory for every case
    ROOT/work/notes.txt
    ROOT/work/safe-sibling.txt
    ROOT/work/docs/readme.md
    ROOT/work/SharedData -> ROOT/protected-share   (symlink into the area)
    ROOT/other/a.txt                unrelated files outside the area

and returns the guard config. Case files refer to ROOT as {ROOT}.
"""

import os


def build(root):
    def write(rel, text):
        path = os.path.join(root, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(text)

    write("protected-share/secret.txt", "token\n")
    write("protected-share/sub/deep.txt", "token\n")
    write("work/notes.txt", "token\n")
    write("work/safe-sibling.txt", "hello\n")
    write("work/docs/readme.md", "# readme\n")
    write("other/a.txt", "hello\n")
    os.symlink(os.path.join(root, "protected-share"), os.path.join(root, "work", "SharedData"))
    return {
        "protected_prefixes": [os.path.join(root, "protected-share")],
        "protected_names": ["SharedData"],
    }


CWD = "work"
