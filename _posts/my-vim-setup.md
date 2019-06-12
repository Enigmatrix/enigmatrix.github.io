---
date: Wed 12 Jun 2019 12:12:28 PM
desc: How I setup my Vim so that I can be productive.
tags:
  - vim
  - config
---

# My Vim Setup

`Vim` is probably one of the most powerful text editors out there. I use it for working on my projects, writing quick scripts, and even writing this blog post.I've setup my `vim` to be a JavaScript, TypeScript and Python IDE, without much performance degradation. 'How is that even possible?', you might ask. 'Vim cannot be an IDE!', shouts the unconvinced watcher.

First things first, ditch the default `vim`. Yes, I know i've been touting the benefits of `vim` so far, but theres a better alternative: `neovim`. Use the unstable build of [`neovim`](https://github.com/neovim/neovim/releases) (atleast `0.4`). It is much faster and has more features, and the bugs are not that big of an issue. 

Even the default `neovim` needs to be extended to fit our needs of an IDE. We use plugins to do this, via a plugin manager called [vim-plug](https://github.com/junegunn/vim-plug). Let's configure our `neovim` to use the plugin manager.

``` vim
" vim-plug auto setup
let plugpath = expand('<sfile>:p:h'). '/autoload/plug.vim'
if !filereadable(plugpath)
    if executable('curl')
        let plugurl = 'https://raw.githubusercontent.com/junegunn/vim-plug/master/plug.vim'
        call system('curl -fLo ' . shellescape(plugpath) . ' --create-dirs ' . plugurl)
        if v:shell_error
            echom "Error downloading vim-plug. Please install it manually.\n"
            exit
        endif
    else
        echom "vim-plug not installed. Please install it manually or install curl.\n"
        exit
    endif
endif

call plug#begin('~/.local/share/nvim/plugged')

" Plugins go here

call plug#end()
```

Put the above code into the `neovim` configuration file, usually `~/.config/nvim/init.vim`. Code (written in VimL) in the file is loaded on startup to initialize our `neovim` to our liking. We will be adding more configuration to this file, so keep note. Next, its time to go shopping!

There are quite a lot of plugins available to `vim`, and by extension, `neovim`. The best place to find the most useful ones are through [vimawesome](https://vimawesome.com/)
