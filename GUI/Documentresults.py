# This file was generated by the Tkinter Designer by Parth Jadhav
# https://github.com/ParthJadhav/Tkinter-Designer

from pathlib import Path
from tkinter import Tk, Canvas, Text, Button, PhotoImage


OUTPUT_PATH = Path(__file__).parent
ASSETS_PATH = OUTPUT_PATH / Path(r"assets/frame6")


def relative_to_assets(path: str) -> Path:
    return ASSETS_PATH / Path(path)


# Initialize the main window
window = Tk()
window.geometry("1619x1113")
window.configure(bg="#000212")

canvas = Canvas(
    window,
    bg="#000212",
    height=1113,
    width=1619,
    bd=0,
    highlightthickness=0,
    relief="ridge"
)
canvas.place(x=0, y=0)

# Add images and text elements to the canvas
image_image_1 = PhotoImage(file=relative_to_assets("image_1.png"))
canvas.create_image(809.0, 578.421142578125, image=image_image_1)

image_image_2 = PhotoImage(file=relative_to_assets("image_2.png"))
canvas.create_image(324.2451171875, 79.752685546875, image=image_image_2)

canvas.create_text(
    55.1826171875,
    147.7994384765625,
    anchor="nw",
    text="Document Scan Completed Successfully!",
    fill="#FFFFFF",
    font=("Inter", 33 * -1)
)

canvas.create_text(
    57.162109375,
    354.9652099609375,
    anchor="nw",
    text="Detailed Result:",
    fill="#FFFFFF",
    font=("Inter", 16 * -1)
)

canvas.create_text(
    57.162109375,
    232.267578125,
    anchor="nw",
    text="Scan Result:",
    fill="#FFFFFF",
    font=("Inter", 16 * -1)
)

canvas.create_text(
    55.2451171875,
    962.9056396484375,
    anchor="nw",
    text="Would you like to generate a detailed report of the results?",
    fill="#FFFFFF",
    font=("Inter", 16 * -1)
)

# Entry widget to display the detailed results
entry_image_1 = PhotoImage(file=relative_to_assets("entry_1.png"))
canvas.create_image(810.5810546875, 661.674560546875, image=entry_image_1)

entry_1 = Text(
    bd=0,
    bg="#19284D",
    fg="#FFFFFF",
    font=("Inter", 14),  # Adjust font size for readability
    highlightthickness=0,
    wrap="word"
)
entry_1.place(
    x=62.162109375,
    y=397.7908935546875,
    width=1496.837890625,
    height=525.767333984375
)

# Add buttons
button_image_1 = PhotoImage(file=relative_to_assets("button_1.png"))
button_1 = Button(
    image=button_image_1,
    borderwidth=0,
    highlightthickness=0,
    command=lambda: print("Generate Report Clicked"),  # Placeholder for button functionality
    relief="flat"
)
button_1.place(
    x=54.9130859375,
    y=1007.924560546875,
    width=209.6982421875,
    height=54.80989456176758
)

button_image_2 = PhotoImage(file=relative_to_assets("button_2.png"))
button_2 = Button(
    image=button_image_2,
    borderwidth=0,
    highlightthickness=0,
    command=window.destroy,  # Close the window
    relief="flat"
)
button_2.place(
    x=274.83984375,
    y=1007.9515380859375,
    width=209.6982421875,
    height=54.80989456176758
)

entry_image_2 = PhotoImage(file=relative_to_assets("entry_2.png"))
canvas.create_image(810.5810546875, 304.69647216796875, image=entry_image_2)

entry_2 = Text(
    bd=0,
    bg="#19284D",
    fg="#FFFFFF",
    font=("Inter", 14),
    highlightthickness=0,
    wrap="word"
)
entry_2.place(
    x=62.162109375,
    y=277.28662109375,
    width=1496.837890625,
    height=52.8197021484375
)


def display_results():
    try:
        # Read the results from the text file
        with open("document_result.txt", "r") as f:
            result_data = f.read()
        print(f"Displaying Results:\n{result_data}")  # Debugging

        # Insert the results into the `entry_1` widget
        entry_1.insert("1.0", result_data)
    except FileNotFoundError:
        print("Error: Results file not found.")
        entry_1.insert("1.0", "Error: Results file not found.")


# Call the function to display results
display_results()

window.resizable(True, True)
window.mainloop()
