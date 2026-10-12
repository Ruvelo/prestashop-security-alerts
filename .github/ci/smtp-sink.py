"""A throwaway SMTP server for CI: writes every message it receives to a directory as .eml."""
import asyncio
import os
import sys
import time

from aiosmtpd.controller import Controller

target = sys.argv[1]
os.makedirs(target, exist_ok=True)


class Sink:
    async def handle_DATA(self, server, session, envelope):
        name = f"{int(time.time() * 1000)}-{len(os.listdir(target))}.eml"
        with open(os.path.join(target, name), "wb") as handle:
            handle.write(envelope.content)
        return "250 OK"


controller = Controller(Sink(), hostname="127.0.0.1", port=1025)
controller.start()
print("smtp sink on 127.0.0.1:1025, writing to", target, flush=True)
try:
    asyncio.get_event_loop().run_forever()
except KeyboardInterrupt:
    controller.stop()
