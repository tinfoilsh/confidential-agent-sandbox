while IFS= read -r setting; do
    export "$setting"
done < /etc/environment
unset setting
# Launchers supply Monitor placeholders before invoking the measured tools.
export PATH="/usr/local/bin:$PATH"
