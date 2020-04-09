![Screen1](https://i.imgur.com/v6K9PNz.png)
# UnrealEngine4-SwissKnife
Reversing Tool designed for Unreal Engine4 to debugg objects JIT

This project allows you to inspect all UObjects under GEngine World's Actors array.
It should work for many UE4 games without much effort, for other games you can always modify it.

The tool works as a websocket listening to request and streaming information about the objects and fields.

The interface is in the html file, this should allow easy modification to anyone needs.

It also has script support to allow for easing modifications and information sharing.


# Dependencies

https://github.com/websockets/ws - For Websockets

https://github.com/ThePhD/sol2 - For Lua
