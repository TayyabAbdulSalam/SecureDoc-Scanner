
# This file was generated by the Tkinter Designer by Parth Jadhav
# https://github.com/ParthJadhav/Tkinter-Designer

from tkinter.filedialog import askopenfilename
import os

from pathlib import Path

# from tkinter import *
# Explicit imports to satisfy Flake8
from tkinter import Tk, Canvas, Entry, Text, Button, PhotoImage

# Store file path globally for passing to the analyzer
uploaded_file_path = ""

OUTPUT_PATH = Path(__file__).parent
ASSETS_PATH = OUTPUT_PATH / Path(r"assets/frame4")


def upload_file():
    global uploaded_file_path
    uploaded_file_path = askopenfilename(filetypes=[("Document Files", "*.pdf *.doc *.docx *.rtf *.html *.txt")])
    if uploaded_file_path:
        print(f"Uploaded file: {uploaded_file_path}")  # Debugging
        # Save the file path to a temporary file
        with open("/tmp/uploaded_file_path.txt", "w") as f:
            f.write(uploaded_file_path)
        # Automatically navigate to the next screen after uploading
        window.destroy()
        os.system("python3 Documentuploaded.py")
    else:
        print("No file selected.")

def relative_to_assets(path: str) -> Path:
    return ASSETS_PATH / Path(path)


window = Tk()

window.geometry("1619x924")
window.configure(bg = "#000212")


canvas = Canvas(
    window,
    bg = "#000212",
    height = 924,
    width = 1619,
    bd = 0,
    highlightthickness = 0,
    relief = "ridge"
)

canvas.place(x = 0, y = 0)
image_image_1 = PhotoImage(
    file=relative_to_assets("image_1.png"))
image_1 = canvas.create_image(
    809.0,
    462.421142578125,
    image=image_image_1
)

image_image_2 = PhotoImage(
    file=relative_to_assets("image_2.png"))
image_2 = canvas.create_image(
    324.245361328125,
    79.752685546875,
    image=image_image_2
)

image_image_3 = PhotoImage(
    file=relative_to_assets("image_3.png"))
image_3 = canvas.create_image(
    809.0,
    491.6396484375,
    image=image_image_3
)

button_image_1 = PhotoImage(
    file=relative_to_assets("button_1.png"))
button_1 = Button(
    image=button_image_1,
    borderwidth=0,
    highlightthickness=0,
    command=upload_file,  # Call upload_file and navigate automatically
    relief="flat"
)
button_1.place(
    x=54.7958984375,
    y=769.1822509765625,
    width=1509.2041015625,
    height=54.80989456176758
)

image_image_4 = PhotoImage(
    file=relative_to_assets("image_4.png"))
image_4 = canvas.create_image(
    809.0,
    491.0,
    image=image_image_4
)

canvas.create_text(
    55.18281555175781,
    148.7994384765625,
    anchor="nw",
    text="Simply upload or drag and drop your document here:",
    fill="#FFFFFF",
    font=("Inter", 33 * -1)
)
window.resizable(True, True)
window.mainloop()
