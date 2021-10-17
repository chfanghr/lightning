> Project archived: I have been permanently baned from using qq lmfao

# lightning [![stability-wip](https://img.shields.io/badge/stability-wip-lightgrey.svg)](https://github.com/mkenney/software-guides/blob/master/STABILITY-BADGES.md#work-in-progress) [![Go](https://github.com/chfanghr/lightning/actions/workflows/go.yml/badge.svg)](https://github.com/chfanghr/lightning/actions/workflows/go.yml)

The purpose of this project is to forward messages between a `qq` group and a `telegram` group.

## Getting Started

1. Clone this project: `git clone https://github.com/chfanghr/lightning.git`
2. Get dependencies by running [`get_dependencies.sh`](get_dependencies.sh) in the root of the repository
3. Fill the configuration file, save it as `config.json`
    - Please refer to [`config.json.example`](config.json.example)
    - Redis configuration can be ignored if you use `docker-compose` to deploy this project
4. Run `docker-compose build`
5. Run `docker-compose up -d`
6. Run `docker-compose logs -f` if you use qr code to log in to qq
7. Enjoy!

## Features

- [x] Forward text messages
- [x] Forward images
- [x] Recall messages from both `telegram` and `qq`
- [x] Forward telegram static stickers(including `gif`s)
- [x] Forward telegram tgs/animated stickers
- [ ] Reply to forwarded messages (wip)
## Troubleshooting

* The program always fails to send (text) messages to qq:
    - remove `session.token` and `device.json` in the `userdata` folder
    - restart services using `docker-compose restart`
    - log in to `qq` (if needed) again

## Related Projects

* [MiraiGo](https://github.com/Mrs4s/MiraiGo/) is a state-of-the-art reverse-engineering project. It provides unofficial
  qq apis.
* [telebot](https://github.com/tucnak/telebot) is a really nice telegram bot api framework.
* [rlottie-to-gif-api](https://github.com/chfanghr/rlottie-to-gif-api) converts telegram animated stickers to gif images
  so that we can send them to qq.

## License

Licensed under the [MIT](LICENSE) license.
