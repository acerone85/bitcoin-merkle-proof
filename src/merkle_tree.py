import hash_functions


class Cell:
    def __init__(self, *args):
        if (len(args) == 0):
            self.is_leaf = True
            self.init_with_value(None)

        elif (len(args) == 1):
            self.is_leaf = True
            self.init_with_value(args[0])

        elif (len(args) == 2):
            self.is_leaf = False
            self.init_with_children(args[0], args[1])
        else:
            raise Exception("Provide either a value or two children cells")

    def init_with_value(self, value):
        self.value = value

    def init_with_children(self, left, right):
        self.left = left
        self.right = right

    def str_helper(self, indent):
        newline = '\n'
        if (self.is_leaf):
            if (self.value == None):
                return "Empty"
            return bytes.hex(self.value)
        else:
            strings = list()
            if (self.left != None):
                strings.append(
                    f"{indent + '  '}Left=[{self.left.str_helper(indent + '  ')}]")

            if (self.right != None):
                strings.append(
                    f"{indent + '  '}Right=[{self.right.str_helper(indent + '  ')}]")

            return f"Tree({newline}{newline.join(strings)}{newline}{indent})"

    def __str__(self):
        return self.str_helper('')

    def set_value(self, value):
        self.is_leaf = True
        self.left = None
        self.right = None
        self.value = value

    def has_left_child(self):
        return self.is_leaf == False & self.left != None

    def has_right_child(self):
        return self.is_leaf == False & self.right != None

    def verify_merkle_proof(self, merkle_proof, flags):
        if (self.is_leaf or flags[0] == '0'):
            self.set_value(merkle_proof[0])
            merkle_proof = merkle_proof[1::]
            flags = flags[1::]
            return (merkle_proof, flags, self.value)
        else:
            flags = flags[1::]

            (merkle_proof, flags, left_hash) = self.left.verify_merkle_proof(
                merkle_proof, flags)
            if (self.right == None):
                right_hash = left_hash

            else:
                (merkle_proof, flags, right_hash) = self.right.verify_merkle_proof(
                    merkle_proof, flags)
            hash = hash_functions.concat_dsha256(
                left_hash, right_hash)
            return (merkle_proof, flags, hash)


class Tree:
    def __init__(self, number_of_leaves):
        if (number_of_leaves == 0):
            raise Exception("Merkle tree must have at least one leave")

        leaves = list(map(lambda _: Cell(None),
                      range(0, number_of_leaves, 1)))
        self.construct(leaves)

    def construct(self, current_level):
        if (len(current_level) == 1):
            self.root = current_level[0]
            return

        i = 0
        next_level = list()
        while (i < len(current_level)):
            left_child = current_level[i]
            if (i+1 == len(current_level)):
                right_child = None
            else:
                right_child = current_level[i+1]
            next_level.append(Cell(left_child, right_child))
            i += 2
        self.construct(next_level)

    def compute_merkle_root(self, merkle_proof, flags):
        flags = [*flags]
        merkle_proof_as_bytes = list(
            map(lambda x: bytes.fromhex(x), merkle_proof))
        (_, _, merkle_root) = self.root.verify_merkle_proof(
            merkle_proof_as_bytes,
            flags
        )
        return bytes.hex(merkle_root)


def compute_merkle_tree(merkle_proof_output):
    n_txs = merkle_proof_output['number_txs']
    hashes = merkle_proof_output['hashes']
    flag = merkle_proof_output['flag']
    tree = Tree(n_txs)
    merkle_root = tree.compute_merkle_root(hashes, flag)
    return (merkle_root, tree)
