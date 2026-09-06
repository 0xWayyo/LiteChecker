"""Small line-oriented terminal views; no terminal modes or background threads."""

import unicodedata


def emit(text: str = "") -> None:
    print(text, flush=True)


def prompt(label: str) -> str:
    # PowerShell's Out-Host forwards complete lines. input(label) flushes bytes,
    # but without a newline its label remains invisible until AFTER the answer.
    # Echo belongs to the terminal; never print the returned value ourselves.
    emit("\n  " + label)
    return input("")


def display_text(value: str) -> str:
    return "".join(char if char.isprintable() else " " for char in value)


def frame(title: str, rows: tuple[str, ...] = (), *, output=emit) -> None:
    width = 50
    def cells(text):
        return sum(0 if unicodedata.combining(char) else
                   2 if unicodedata.east_asian_width(char) in {"W", "F"} else 1 for char in text)
    def row(text):
        text = display_text(text)
        while cells(text) > width - 4:
            text = text[:-1]
        output("  │  " + text + " " * (width - 2 - cells(text)) + "│")
    output("")
    output("  ┌" + "─" * width + "┐")
    row(title)
    if rows:
        output("  ├" + "─" * width + "┤")
        for text in rows:
            row(text)
    output("  └" + "─" * width + "┘")
