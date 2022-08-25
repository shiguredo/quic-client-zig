import argparse
import logging
from aioquic.asyncio import serve
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.logger import QuicFileLogger
import asyncio


async def main(host: str, port: int, config: QuicConfiguration):
    conn = await serve(host, port, configuration=config)
    await asyncio.Future()

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('host', type=str)
    parser.add_argument('port', type=int)
    parser.add_argument('certificate', type=str)
    parser.add_argument('private', type=str)
    parser.add_argument('log_file', type=str)

    args = parser.parse_args()

    logging.basicConfig(
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        level=logging.DEBUG,
    )

    logger = QuicFileLogger(args.log_file)

    config = QuicConfiguration(
        is_client=False,
        max_datagram_frame_size=2**16,
        quic_logger=logger,
    )
    config.load_cert_chain(args.certificate, args.private)

    try:
        asyncio.run(main(
            host=args.host,
            port=args.port,
            config=config,
        ))
    except KeyboardInterrupt:
        pass