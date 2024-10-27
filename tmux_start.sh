tmux new-session -c /home/odespo/com/projects/rust-auth -s rust_auth -d vim \; split-window -d "bash" \; select-layout main-vertical \; set-option main-pane-width 75% \; swap-pane -s 0 -t 1 \; attach
