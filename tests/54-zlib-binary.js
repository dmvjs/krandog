import zlib from 'zlib';

// Binary data with null bytes
const original = Buffer.from([72, 101, 108, 108, 111, 0, 87, 111, 114, 108, 100, 0, 33]);

console.log('original length:', original.length);
console.log('original first:', original[0]);
console.log('original last:', original[original.length - 1]);

zlib.gzip(original, (err, compressed) => {
  if (err) {
    console.log('compression error:', err);
    return;
  }

  console.log('compressed length:', compressed.length);
  console.log('compressed type:', compressed.constructor.name);

  zlib.gunzip(compressed, (err, decompressed) => {
    if (err) {
      console.log('decompression error:', err);
      return;
    }

    console.log('decompressed length:', decompressed.length);
    console.log('decompressed first:', decompressed[0]);
    console.log('decompressed last:', decompressed[decompressed.length - 1]);
    console.log('match:', decompressed.length === original.length);
  });
});
