-- dualview.nvim
-- Splits the screen horizontally, displaying two buffers centered in each split.
-- Designed for use with: nvim -p file_one file_two
-- Supports directory iteration: press 'q' to advance to the next _vuln/_mitigated pair.

local M = {}

local state = {
  active                  = false,
  top_win                 = nil,
  bot_win                 = nil,
  top_buf                 = nil,   -- original source buffers
  bot_buf                 = nil,
  top_scratch             = nil,   -- scratch buffers used for display
  bot_scratch             = nil,
  numbers_visible         = false,
  original_settings       = {},
  original_global         = {},    -- saved global options
  original_cursor_hl      = nil,   -- saved Cursor highlight
  original_guicursor      = nil,   -- saved guicursor
  original_winsep_hl      = nil,   -- saved WinSeparator highlight
  original_statusline_hl  = nil,   -- saved StatusLine highlight
  original_statuslinenc_hl = nil,  -- saved StatusLineNC highlight

  -- Iterator state
  pairs_list              = {},    -- { { vuln = "...", mitigated = "..." }, ... }
  current_pair            = 0,     -- index into pairs_list (0 = not iterating)
}

-- Window-local options to strip for zen display
local ZEN_WIN_OPTS = {
  number         = false,
  relativenumber = false,
  signcolumn     = "no",
  foldcolumn     = "0",
  statusline     = " ",
  cursorline     = false,
  list           = false,
}

-- Global options to override for zen display
local ZEN_GLOBAL_OPTS = {
  laststatus  = 0,
  showtabline = 0,
  cmdheight   = 0,
  fillchars   = "eob: ,vert: ,horiz: ,horizup: ,horizdown: ,vertleft: ,vertright: ,verthoriz: ",
}

local function save_win_opts(win)
  local saved = {}
  for opt, _ in pairs(ZEN_WIN_OPTS) do
    saved[opt] = vim.wo[win][opt]
  end
  saved.winbar = vim.wo[win].winbar
  return saved
end

local function restore_win_opts(win, saved)
  if not vim.api.nvim_win_is_valid(win) then return end
  for opt, val in pairs(saved) do
    vim.wo[win][opt] = val
  end
end

local function save_global_opts()
  local saved = {}
  for opt, _ in pairs(ZEN_GLOBAL_OPTS) do
    saved[opt] = vim.o[opt]
  end
  return saved
end

local function apply_global_opts()
  for opt, val in pairs(ZEN_GLOBAL_OPTS) do
    vim.o[opt] = val
  end
end

local function restore_global_opts(saved)
  for opt, val in pairs(saved) do
    vim.o[opt] = val
  end
end

local function apply_zen_opts(win)
  for opt, val in pairs(ZEN_WIN_OPTS) do
    vim.wo[win][opt] = val
  end
end

-- Build a scratch buffer with content horizontally and vertically centered
local function make_centered_buf(source_buf, win)
  if not vim.api.nvim_win_is_valid(win) then return vim.api.nvim_create_buf(false, true) end
  local lines      = vim.api.nvim_buf_get_lines(source_buf, 0, -1, false)
  local win_width  = vim.api.nvim_win_get_width(win)
  local win_height = vim.api.nvim_win_get_height(win) - 1  -- account for winbar

  local max_len = 0
  for _, line in ipairs(lines) do
    local len = vim.fn.strdisplaywidth(line)
    if len > max_len then max_len = len end
  end

  local hpad   = math.max(0, math.floor((win_width - max_len) / 2))
  local prefix = string.rep(" ", hpad)
  local vpad   = math.max(0, math.floor((win_height - #lines) / 2))

  local padded = {}
  for _ = 1, vpad do
    table.insert(padded, "")
  end
  for _, line in ipairs(lines) do
    table.insert(padded, prefix .. line)
  end

  local scratch = vim.api.nvim_create_buf(false, true)
  vim.api.nvim_buf_set_lines(scratch, 0, -1, false, padded)

  local ft = vim.bo[source_buf].filetype
  if ft and ft ~= "" then
    vim.bo[scratch].filetype = ft
  end

  vim.bo[scratch].modifiable = false
  vim.bo[scratch].bufhidden  = "wipe"
  vim.bo[scratch].buflisted  = false

  return scratch
end

local function wipe_scratch(buf)
  if buf and vim.api.nvim_buf_is_valid(buf) then
    vim.api.nvim_buf_delete(buf, { force = true })
  end
end

local function setup_split(win, source_buf, winbar)
  state.original_settings[win] = save_win_opts(win)
  local scratch = make_centered_buf(source_buf, win)
  vim.api.nvim_win_set_buf(win, scratch)
  apply_zen_opts(win)
  vim.wo[win].winbar = winbar
  return scratch
end

local function rebuild_scratches()
  if state.top_win and vim.api.nvim_win_is_valid(state.top_win) then
    vim.api.nvim_win_set_buf(state.top_win, state.top_buf)
    wipe_scratch(state.top_scratch)
    state.top_scratch = make_centered_buf(state.top_buf, state.top_win)
    vim.api.nvim_win_set_buf(state.top_win, state.top_scratch)
    apply_zen_opts(state.top_win)
    vim.wo[state.top_win].winbar = "%#DualviewTop# vulnerable"
  end

  if state.bot_win and vim.api.nvim_win_is_valid(state.bot_win) then
    vim.api.nvim_win_set_buf(state.bot_win, state.bot_buf)
    wipe_scratch(state.bot_scratch)
    state.bot_scratch = make_centered_buf(state.bot_buf, state.bot_win)
    vim.api.nvim_win_set_buf(state.bot_win, state.bot_scratch)
    apply_zen_opts(state.bot_win)
    vim.wo[state.bot_win].winbar = "%#DualviewBot# mitigated"
  end
end

-- ─── Iterator ─────────────────────────────────────────────────────────────────

-- Scan cwd for _vuln / _mitigated pairs, sorted
local function collect_pairs()
  local pairs_list = {}
  local handle = io.popen("ls 2>/dev/null | sort")
  if handle then
    for vuln_file in handle:lines() do
      local base, ext = vuln_file:match("^(.-)_vuln(%.[^.]+)$")
      if base then
        local mitigated_file = base .. "_mitigated" .. ext
        local f = io.open(mitigated_file, "r")
        if f then
          f:close()
          table.insert(pairs_list, { vuln = vuln_file, mitigated = mitigated_file })
        end
      end
    end
    handle:close()
  end
  return pairs_list
end

-- Load a file into a buffer (reuse existing or create new)
local function buf_for_file(filepath)
  -- Check if already loaded
  for _, buf in ipairs(vim.api.nvim_list_bufs()) do
    if vim.api.nvim_buf_get_name(buf) == vim.fn.fnamemodify(filepath, ":p") then
      return buf
    end
  end
  local buf = vim.api.nvim_create_buf(true, false)
  vim.api.nvim_buf_set_name(buf, filepath)
  vim.api.nvim_buf_call(buf, function()
    vim.cmd("edit")
  end)
  return buf
end

-- Advance to the next pair, or quit if exhausted
local function next_pair()
  if not state.active then return end

  -- If not iterating yet, initialise
  if state.current_pair == 0 then
    state.pairs_list  = collect_pairs()
    state.current_pair = 1
  else
    state.current_pair = state.current_pair + 1
  end

  if state.current_pair > #state.pairs_list then
    vim.notify("dualview: all pairs reviewed!", vim.log.levels.INFO)
    M.deactivate()
    vim.cmd("qa")
    return
  end

  local pair  = state.pairs_list[state.current_pair]
  local total = #state.pairs_list

  -- Unlist old iteration bufs to keep buffer list clean (but don't force delete)
  if state.current_pair > 1 then
    if vim.api.nvim_buf_is_valid(state.top_buf) then
      vim.bo[state.top_buf].buflisted = false
    end
    if vim.api.nvim_buf_is_valid(state.bot_buf) then
      vim.bo[state.bot_buf].buflisted = false
    end
  end

  -- Load fresh buffers for this pair
  state.top_buf = buf_for_file(pair.vuln)
  state.bot_buf = buf_for_file(pair.mitigated)

  -- Rebuild the centered display with updated winbar showing progress
  if state.top_win and vim.api.nvim_win_is_valid(state.top_win) then
    -- Set window to source buf first so wiping the scratch doesn't close the window
    vim.api.nvim_win_set_buf(state.top_win, state.top_buf)
    wipe_scratch(state.top_scratch)
    state.top_scratch = make_centered_buf(state.top_buf, state.top_win)
    vim.api.nvim_win_set_buf(state.top_win, state.top_scratch)
    apply_zen_opts(state.top_win)
    vim.wo[state.top_win].winbar = string.format(
      "%%#DualviewTop# vulnerable  [%d/%d] %s", state.current_pair, total, pair.vuln
    )
  end

  if state.bot_win and vim.api.nvim_win_is_valid(state.bot_win) then
    -- Set window to source buf first so wiping the scratch doesn't close the window
    vim.api.nvim_win_set_buf(state.bot_win, state.bot_buf)
    wipe_scratch(state.bot_scratch)
    state.bot_scratch = make_centered_buf(state.bot_buf, state.bot_win)
    vim.api.nvim_win_set_buf(state.bot_win, state.bot_scratch)
    apply_zen_opts(state.bot_win)
    vim.wo[state.bot_win].winbar = string.format(
      "%%#DualviewBot# mitigated  [%d/%d] %s", state.current_pair, total, pair.mitigated
    )
  end

  vim.api.nvim_set_current_win(state.top_win)
end

-- ─── Public API ───────────────────────────────────────────────────────────────

function M.activate()
  if state.active then return end

  local bufs = {}
  for _, buf in ipairs(vim.api.nvim_list_bufs()) do
    if vim.api.nvim_buf_is_loaded(buf) and vim.bo[buf].buflisted then
      table.insert(bufs, buf)
      if #bufs == 2 then break end
    end
  end

  if #bufs < 2 then
    vim.notify(
      "dualview: need at least 2 loaded buffers (use nvim -p file1 file2)",
      vim.log.levels.ERROR
    )
    return
  end

  state.top_buf = bufs[1]
  state.bot_buf = bufs[2]

  state.original_global          = save_global_opts()
  state.original_guicursor       = vim.o.guicursor
  state.original_cursor_hl       = vim.api.nvim_get_hl(0, { name = "Cursor" })
  state.original_winsep_hl       = vim.api.nvim_get_hl(0, { name = "WinSeparator" })
  state.original_statusline_hl   = vim.api.nvim_get_hl(0, { name = "StatusLine" })
  state.original_statuslinenc_hl = vim.api.nvim_get_hl(0, { name = "StatusLineNC" })

  local normal_hl = vim.api.nvim_get_hl(0, { name = "Normal" })
  local bg = string.format("#%06x", normal_hl.bg or 0x252525)

  vim.api.nvim_set_hl(0, "CursorHidden",  { blend = 100, fg = "#000000", bg = "#000000" })
  vim.o.guicursor = "a:CursorHidden"

  vim.api.nvim_set_hl(0, "WinSeparator",  { fg = bg, bg = bg })
  vim.api.nvim_set_hl(0, "StatusLine",    { fg = bg, bg = bg })
  vim.api.nvim_set_hl(0, "StatusLineNC",  { fg = bg, bg = bg })

  vim.api.nvim_set_hl(0, "DualviewTop", { fg = "#ffffff", bg = "#cc0000", bold = true })
  vim.api.nvim_set_hl(0, "DualviewBot", { fg = "#ffffff", bg = "#0055cc", bold = true })

  vim.cmd("only")
  local top_win = vim.api.nvim_get_current_win()
  vim.api.nvim_win_set_buf(top_win, state.top_buf)

  vim.cmd("split")
  local bot_win = vim.api.nvim_get_current_win()
  vim.api.nvim_win_set_buf(bot_win, state.bot_buf)

  vim.cmd("wincmd =")

  state.top_win         = top_win
  state.bot_win         = bot_win
  state.active          = true
  state.numbers_visible = false
  state.current_pair    = 0   -- reset iterator

  apply_global_opts()

  state.top_scratch = setup_split(top_win, state.top_buf, "%#DualviewTop# vulnerable")
  state.bot_scratch = setup_split(bot_win, state.bot_buf, "%#DualviewBot# mitigated")

  vim.api.nvim_set_current_win(top_win)

  -- Tab advances to the next pair while dualview is active
  vim.keymap.set("n", "<Tab>", function()
    if state.active then next_pair() end
  end, { desc = "dualview: next pair", silent = true, nowait = true })
end

function M.deactivate()
  if not state.active then return end

  pcall(vim.keymap.del, "n", "<Tab>")

  restore_global_opts(state.original_global)

  if state.original_guicursor then
    vim.o.guicursor = state.original_guicursor
  end
  if state.original_cursor_hl then
    vim.api.nvim_set_hl(0, "Cursor", state.original_cursor_hl)
  end
  vim.api.nvim_set_hl(0, "CursorHidden", {})

  if state.original_winsep_hl then
    vim.api.nvim_set_hl(0, "WinSeparator", state.original_winsep_hl)
  end
  if state.original_statusline_hl then
    vim.api.nvim_set_hl(0, "StatusLine", state.original_statusline_hl)
  end
  if state.original_statuslinenc_hl then
    vim.api.nvim_set_hl(0, "StatusLineNC", state.original_statuslinenc_hl)
  end

  if state.top_win and vim.api.nvim_win_is_valid(state.top_win) then
    vim.api.nvim_win_set_buf(state.top_win, state.top_buf)
    restore_win_opts(state.top_win, state.original_settings[state.top_win] or {})
  end
  if state.bot_win and vim.api.nvim_win_is_valid(state.bot_win) then
    vim.api.nvim_win_set_buf(state.bot_win, state.bot_buf)
    restore_win_opts(state.bot_win, state.original_settings[state.bot_win] or {})
  end

  wipe_scratch(state.top_scratch)
  wipe_scratch(state.bot_scratch)

  state.active                   = false
  state.top_win                  = nil
  state.bot_win                  = nil
  state.top_scratch              = nil
  state.bot_scratch              = nil
  state.original_settings        = {}
  state.original_global          = {}
  state.original_cursor_hl       = nil
  state.original_guicursor       = nil
  state.original_winsep_hl       = nil
  state.original_statusline_hl   = nil
  state.original_statuslinenc_hl = nil
  state.pairs_list               = {}
  state.current_pair             = 0
end

function M.toggle_numbers()
  if not state.active then return end
  state.numbers_visible = not state.numbers_visible
  for _, win in ipairs({ state.top_win, state.bot_win }) do
    if win and vim.api.nvim_win_is_valid(win) then
      vim.wo[win].number         = state.numbers_visible
      vim.wo[win].relativenumber = false
    end
  end
end

function M.recenter()
  if not state.active then return end
  vim.cmd("wincmd =")
  rebuild_scratches()
end

function M.setup(opts)
  opts = opts or {}
  local leader = opts.leader or "<leader>"

  if opts.keymaps ~= false then
    local map = function(lhs, fn, desc)
      vim.keymap.set("n", lhs, fn, { desc = desc, silent = true })
    end
    map(leader .. "da", M.activate,       "dualview: activate")
    map(leader .. "dq", M.deactivate,     "dualview: deactivate")
    map(leader .. "dn", M.toggle_numbers, "dualview: toggle line numbers")
    map(leader .. "dr", M.recenter,       "dualview: recenter splits")
  end

  vim.api.nvim_create_autocmd("VimResized", {
    callback = function()
      if state.active then
        vim.schedule(M.recenter)
      end
    end,
    desc = "dualview: recenter on resize",
  })
end

return M

