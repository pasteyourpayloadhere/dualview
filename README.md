### dualview.nvim

A minimal Neovim plugin that splits the screen horizontally and displays two buffers centered in each split, with a zen-style stripped UI.

Designed for use with `nvim -p file_one file_two`, with built-in support for iterating through `_vuln` / `_mitigated` file pairs in a directory.

<img src="https://autcsi.nz/web-security-workshop/nvim-plugin-dualview.gif" width="840" />

### Motions


| Key | Action |
|-----|--------|
| `<leader>da` | Activate dualview |
| `<leader>dq` | Deactivate / restore UI |
| `<leader>dn` | Toggle line numbers on/off |
| `<leader>dr` | Recenter both splits |
| `<Tab>` | Advance to the next `_vuln` / `_mitigated` pair *(active only while dualview is running)* |


### Usage

```bash
nvim -p file_one.py file_two.py
```

Then press `<leader>da` to activate.

### Installation

### lazy.nvim

```lua
{
  "pasteyourpayloadhere/dualview",
  config = function()
    require("dualview").setup({
      leader  = "<leader>",
      keymaps = true,
    })
  end,
},
```

