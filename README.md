# olvid-rs

![Welcome screen screenshot](/docs/screenshot-welcome-screen.png)

**olvid-rs** aims to be a full rust implementation of the Olvid messaging system usable from a Terminal User Interface (because why not).
Olvid technical specifications can be found [here](https://olvid.io/assets/documents/2024-10-07_Olvid-specifications.pdf)
The Olvid iOS and Android apps are also [open-source](https://github.com/olvid-io) and are a great way to learn more about implementation details.

## Disclaimer

[!WARNING]  
While I aspire for this project to be functional eventually, its primary purpose for me is educational.
I sought a project to delve into Rust, cryptography, and secure messaging systems, and this one fits perfectly. The comprehensive specifications provided by Olvid, along with their open-source projects, offer invaluable insights into the underlying components of their system.

## Project Structure

![Project structure diagram](/docs/olvid-rs-project-structure.png)

olvid-rs is divided in multiples crates:
- **core** - low-level APIs, aims to implement parts II and III of Olvid specifications document. 
- **engine** - high-level APIs, aims to implement parts IV to X of Olvid specifications document, plus provides a peristence layer with SQLite. This crate can be used by any end-user app that wish to provide Olvid messaging easily.
- **tui** - end-user interface

## Project status: early stage
### core
**core** crate is kind of usable even though it will be seriously refactored at some point because I didn't know that much rust when I started working on this (and I still have a lot to learn).

### engine and tui
Very (very) early stage overall. 
TUI fondations are there: components system, basic inputs etc...

### Improvements priorities:
- Better error handling
- Use crypto-secure Big Integers
- Performance improvements

Also, Olvid cryptographic primitives are tested with the exact same test vectors of the Olvid Android App but I obviously want to add way more tests.