# Working with GPT-2-Simple

This walkthrough will explain how to get a working setup for Python's `gpt-2-simple` library. It includes  implementation of code, along with different adjustments that are required to get it set up on a Windows 10 environment. This guide is intended to be used for research purposes.

# Setup

- Download an install Python 3.7 from the Python project's webpage

- Add the Python/37 directory to your system path, like:

  `C:\Users\<My User>\AppData\Local\Programs\Python\Python37\python.exe`

  *Replace `<My User>` with your user's name.*

- Using the above path, install the following modules:

  `C:\Users\<My User>\AppData\Local\Programs\Python\Python37\python.exe -m tensorflow==1.14.0 gpt-2-simple`

  *Note: This targets the correct version of TensorFlow. gpt-2-simple breaks with later versions.*

# Input file

`gpt-2-simple` accepts a single file as input. It provides you with a sample, `shakespeare.txt`. Of course, you can use any text file as input.

In some cases, you'll need to sanitize the file prior to usage. Otherwise, the app will throw an error and break in the middle of text generation. One way to solve this is by converting the file from UTF-8 to ASCII, then using this sanitized file as the input. (The code solution provides a means to accomplish this in the static `Sanitizer.utf_to_ascii` method.)

# Running the program

If you've never tried GPT-2, know that it will take a long time on most systems. You may want to run it at a time when you can leave the entire system alone for several hours: before going to bed, going to work, etc.

# Python code

The following code was taken from the `gpt-2-simple` Github page. It is distributed into different methods for convenience.

```python
"""
gpt2test - Perform tasks to generate text with the gpt-2-simple engine.
"""
import gpt_2_simple as gpt2
import os
import requests
import traceback
import shutil


class Gpt2:
    """ Runs a GPT2 instance. This is the same functionality as the script
    on the github page, but distributed into different methods. 
    
    Make sure you have the following outdated packages installed:
        
    -   Python 3.7
    -   TensorFlow 1.14.0 for python 3.7 (most recent)
    
    Current implementation just prints the generated text to the console. To
    store the generated text to a file, redirect it to a txt extension.
    """
    
    def __init__(self, file_name="shakespeare.txt", model_name="124M"):

        self.file_name = file_name
        self.model_name = model_name
    
    def setup_model(self):
        """ Create the 'model' folders and files. """
        
        if not os.path.isdir(os.path.join("models", self.model_name)):
            print(f"Downloading {self.model_name} model...")
			
            # model is saved into current directory under /models/124M/
            gpt2.download_gpt2(model_name=self.model_name)   

    def download_default_file(self):
        """ Optional: Use the default Shakespeare input (Julius Caesar?) """
        
        self.file_name = "shakespeare.txt"
        
        if not os.path.isfile(self.file_name):
            
        	url = "https://raw.githubusercontent.com/karpathy/char-rnn/master/data/tinyshakespeare/input.txt"
        	data = requests.get(url)
        	
        	with open(self.file_name, 'w') as f:
        		f.write(data.text)

    def start_session(self):
        """ Start the GPT2 session. """
        self.sess = gpt2.start_tf_sess()

    def finetune(self):
        """ Needed when starting most projects. Train the AI from scratch. """
        
        gpt2.finetune(
                  self.sess,
                  self.file_name,
                  model_name=self.model_name,
                  steps=1000)   # steps is max number of training steps

    def generate(self):
        """ Generate the new text. """
        gpt2.generate(self.sess)
        

class GptApi(Gpt2):
    """ Organize the Gpt2 methods into meaningful tasks. """
    
    def run(self):
        """ Run all components. """   
        self.setup_model()
        self.start_session()
        self.finetune()
        self.generate()
        
    def demo(self):
        """ Same behavior as the script from the Github page. """
        self.download_default_file()
        self.run_all()
        

class Sanitizer:
    """ Handle data/character encoding issues. """
    
    @staticmethod
    def utf_to_ascii(utf_file:str):
        """ Convert a UTF-8 file to ASCII. """   

        sanitized_file = utf_file + ".sanitized"
        
        print("Sanitizing data... ", end="")
        
        # Both files need to be open: in=read, out=write
        with open(utf_file, encoding='utf-8') as infile, \
        open(sanitized_file, 'w', encoding='utf-8') as outfile:
                
            for line in infile:
                
                # Reject any ASCII-hostile characters.
                try: 
                    line = line.encode(encoding="utf-8", errors="ignore")
                    outfile.write(line.decode(encoding="ascii", errors="ignore"))

                except Exception:
                    continue
        
        # Back-up the original, and rename the sanitized copy.
        try:
            shutil.move(utf_file, utf_file+".BAK")
            shutil.move(sanitized_file, utf_file)
            print("Done.")
            
        except Exception:
			print("FAILED!")
            traceback.print_exc()


if __name__ == "__main__":
    
    # Change the hardcoded filename to an argparse variable later.
    # Also, manually edit the filename before running.
    a = {
        "filename" : "your_file.txt"
    }
    
    try:
        Sanitizer.utf_to_ascii(a["filename"])
        g = GptApi(a["filename"])
        g.run()
        
    except Exception as e:
        traceback.print_exc()
                
    print("Done with GPT-2 generator.")
 
```

