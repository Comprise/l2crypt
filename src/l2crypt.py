import io
import os
import zlib

from Crypto.Util.number import bytes_to_long, long_to_bytes


class L2Crypt:
    KEY_111 = int("0xAC", 16)

    MODULUS_413 = int(
        "97df398472ddf737ef0a0cd17e8d172f"
        "0fef1661a38a8ae1d6e829bc1c6e4c3c"
        "fc19292dda9ef90175e46e7394a18850"
        "b6417d03be6eea274d3ed1dde5b5d7bd"
        "e72cc0a0b71d03608655633881793a02"
        "c9a67d9ef2b45eb7c08d4be329083ce4"
        "50e68f7867b6749314d40511d09bc574"
        "4551baa86a89dc38123dc1668fd72d83",
        16,
    )
    MODULUS_ENCDEC = int(
        "75b4d6de5c016544068a1acf125869f4"
        "3d2e09fc55b8b1e289556daf9b875763"
        "5593446288b3653da1ce91c87bb1a5c1"
        "8f16323495c55d7d72c0890a83f69bfd"
        "1fd9434eb1c02f3e4679edfa43309319"
        "070129c267c85604d87bb65bae205de3"
        "707af1d2108881abb567c3b3d069ae67"
        "c3a4c6a3aa93d26413d4c66094ae2039",
        16,
    )

    EXPONENT_413 = int("35", 16)
    EXPONENT_ENCDEC = int("1d", 16)

    @staticmethod
    def out_write(
        out_filename: str,
        result: bytes,
    ) -> None:
        with open(out_filename, mode="wb") as out:
            out.write(result)

    def _decoding_111(
        self,
        file: io.BufferedReader,
    ) -> io.BytesIO:
        data = io.BytesIO()

        for i in file.read():
            data.write(bytes([i ^ self.KEY_111]))

        data.seek(0)
        return data

    @staticmethod
    def _decoding_413(
        file: io.BufferedReader,
        mod: int,
        exp: int,
    ) -> io.BytesIO:
        data = io.BytesIO()
        block = file.read(128)

        while block:
            block_data_bytes = long_to_bytes(pow(bytes_to_long(block), exp, mod))
            block_data_bytes_size = block_data_bytes[0]

            if block_data_bytes_size == 124:
                block_data = block_data_bytes.removeprefix(b"|")
            else:
                block_data = block_data_bytes[1:].lstrip(bytes([0]))[:block_data_bytes_size]

            data.write(block_data)
            block = file.read(128)

        data.seek(0)
        return data

    def decoding(
        self,
        file_path: str,
        original=True,
    ) -> None:
        filename = os.path.basename(file_path)
        out_filename = "dec_" + filename

        with open(file_path, "rb") as file:
            head = file.read(28).decode("UTF-16LE")
            version = int(head.lstrip("Lineage2Ver"))

            match version:
                case 111:
                    data: io.BytesIO = self._decoding_111(file)  # type: ignore[no-redef]
                    self.out_write(out_filename, data.read())
                case 413:
                    mod: int = self.MODULUS_413 if original else self.MODULUS_ENCDEC
                    exp: int = self.EXPONENT_413 if original else self.EXPONENT_ENCDEC

                    data: io.BytesIO = self._decoding_413(file, mod, exp)  # type: ignore[no-redef]

                    data_size_bytes = data.read(4)
                    data_size = int.from_bytes(data_size_bytes, byteorder="little")

                    result = zlib.decompress(data.read())

                    result_size = len(result)

                    if data_size == result_size:
                        self.out_write(out_filename, result)
                case _:
                    ...


l2crypt = L2Crypt()
l2crypt.decoding(file_path="original_files/l2.ini", original=True)
