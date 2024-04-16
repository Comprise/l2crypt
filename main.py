import io
import zlib
import os
from Crypto.Util.number import bytes_to_long, long_to_bytes


class L2Crypt:
    __key = int("0xAC", 16)

    __mod_origin = int(
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
    __mod_no_origin = int(
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

    __exp_no_origin = int("1d", 16)
    __exp_origin = int("35", 16)

    def __init__(self, original: bool = True):
        self._mod = self.__mod_origin if original else self.__mod_no_origin
        self._exp = self.__exp_origin if original else self.__exp_no_origin
        self._filename = None
        self._out_filename = None

    @property
    def filename(self):
        return self._filename

    @filename.setter
    def filename(self, value):
        self._filename = value

    @property
    def out_filename(self):
        return self._out_filename

    @out_filename.setter
    def out_filename(self, value):
        self._out_filename = value

    def _out_write(self, result: bytes):
        with open(self.out_filename, mode="wb") as out:
            out.write(result)

    def _decoding_111(self, file) -> io.BytesIO:
        data = io.BytesIO()

        for i in file.read():
            data.write(bytes([i ^ self.__key]))

        data.seek(0)
        return data

    def _decoding_413(self, file) -> io.BytesIO:
        data = io.BytesIO()
        block = file.read(128)

        while block:
            block_data_bytes = long_to_bytes(pow(bytes_to_long(block), self._exp, self._mod))
            block_data_bytes_size = block_data_bytes[0]

            if block_data_bytes_size == 124:
                block_data = block_data_bytes.removeprefix(b"|")
            else:
                block_data = block_data_bytes[1:].lstrip(bytes([0]))[:block_data_bytes_size]

            data.write(block_data)
            block = file.read(128)

        data.seek(0)
        return data

    def decoding(self, file_path: str):
        self.filename = os.path.basename(file_path)
        self.out_filename = "dec-" + self.filename

        with open(file_path, "rb") as file:
            head = file.read(28).decode("UTF-16LE")
            version = int(head.lstrip("Lineage2Ver"))

            match version:
                case 111:
                    data: io.BytesIO = self._decoding_111(file)
                    self._out_write(result=data.read())
                case 413:
                    data: io.BytesIO = self._decoding_413(file)

                    data_size_bytes = data.read(4)
                    data_size = int.from_bytes(data_size_bytes, byteorder='little')

                    result = zlib.decompress(data.read())

                    result_size = len(result)

                    if data_size == result_size:
                        self._out_write(result)
                case _:
                    ...


l2crypt = L2Crypt(original=True)
l2crypt.decoding(file_path='original_files/l2.ini')
