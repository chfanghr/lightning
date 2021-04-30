#!/usr/bin/env bash

git submodule update --init
cd rlottie-to-gif-api || echo "where the hell is rlottie-to-gif-api???"; exit
git submodule update --init