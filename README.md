# lightning [![Go](https://github.com/chfanghr/lightning/actions/workflows/go.yml/badge.svg)](https://github.com/chfanghr/lightning/actions/workflows/go.yml)

This is a ***WIP*** project.

The purpose of this project is to forward messages between a `qq` group and a `telegram` group.

# Features

- [x] Forward text messages
- [x] Forward images
- [x] Recall messages from both `telegram` and `qq`
- [x] Forward telegram static stickers(including `gif`s)
- [ ] Forward telegram tgs/animated stickers(WIP)

# Troubleshooting

* The program always fails to send (text) messages to qq:
    - remove `session.token` and `device.json` in the `userdata` folder
    - restart the program
    - login to qq again

# License

Licensed under the [MIT](LICENSE) license.
