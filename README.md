# extract_android_ota_payload.py

This utility extracts Android firmware images from an OTA `payload.bin` file. With the A/B system update method, the OTA file format has been revised, and this tool enables the extraction and decompression of firmware images packed using the 'brillo' toolset. Incremental firmware images (such as those using source_copy or source_bsdiff operations) are not supported.

---

## Usage

```shell
$ extract_android_ota_payload.py <payload_file> [target_dir] [--use-local-tools]
  <payload_file>      : Path to the OTA package (either .zip or .bin format)
  [target_dir]        : Directory to save extracted files (default: '.\output')
  [--use-local-tools] : Utilize local `xzcat` and `bzcat` tools if available
```

### Example

To run the utility, ensure your environment is set up with the required Python dependencies:

```shell
(venv) $ extract_android_ota_payload.py q3_50473320109900510.zip output --use-local-tools
```

Expected output:

```
Opening ZIP file q3_50473320109900510.zip to extract to C:\Projects\Python\extract_android_ota_payload\output...
Extracting to target directory: C:\Projects\Python\extract_android_ota_payload\output
Extracting 'boot.img'
[==================================================] 48/48
Extracting 'system.img'
[==================================================] 414/414 
...
Extracting 'vendor.img'
[==================================================] 216/216
```

---

## Precompiled Version for Windows

For Windows users, a precompiled version of this utility is available in the releases section. This version does not require Python to be installed on your system. Simply download and run the executable file.

---

## Using a Virtual Environment

To manage dependencies effectively, use a Python virtual environment. Here’s how:

1. Create a virtual environment:
   ```shell
   py -m venv venv
   ```

2. Activate the virtual environment:
   ```shell
   venv\Scripts\activate.bat
   ```

3. Install dependencies:
   ```shell
   pip install -r requirements.txt
   ```

4. Run the utility:
   ```shell
   extract_android_ota_payload.py <payload_file> [target_dir] [--use-local-tools]
   ```

---

## Dependencies

- `protobuf==3.20.3` (strict version required)

Install by using the `requirements.txt` file:
```shell
pip install -r requirements.txt
```

For local tools option (--use-local-tools):
- Make sure `xzcat` and `bzcat` are installed on your system.
