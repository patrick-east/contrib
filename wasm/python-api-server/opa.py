import pywasm

class Rego:
    wasm_instance = None

    def __init__(self, wasm_file=None, wasm_bytes=None):
        """Rego needs the compiled webassembly to evaluate.
        
        Keyword arguments:
        wasm_file -- (string) Filepath to a *.wasm file to load
        wasm_bytes -- (io.IOBase) Either a file handle or in memory
                       buffer to read the wasm program from.
        """

        memory = pywasm.Memory(pywasm.structure.Limits(5, None))

        imports = {
            "env": {
                "memory": memory,
                "opa_abort": self.__opa_abort
            }
        }

        if wasm_file is not None:
            self.wasm_instance = pywasm.load(wasm_file, imports)
        elif wasm_bytes is not None:
            module = pywasm.structure.Module.from_reader(wasm_bytes)
            self.wasm_instance = pywasm.Runtime(module, imports)
        else:
            raise Exception("Missing required parameter")
    
    def eval_bool(self, input):
        """Evaluate the input with compiled query as a boolean"""
        r = self.eval(input)
        return bool(r)
    
    def _eval(self, input):
        input_length = len(input)
        
        # Allocate memory for the input string
        addr = self.wasm_instance.exec("opa_malloc", input_length)

        # Get a "view" of the address as a uint8 array
        memory = policy.memory.uint8_view(addr)

        # Copy the input string into the memory
        for i in range(input_length):
            memory[i] = input[i]

        return policy.exports.eval(addr, input_length)

    def __opa_abort(addr):
        err_string = addr
        raise Exception(err_string)
