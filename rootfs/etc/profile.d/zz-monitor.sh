while IFS= read -r setting; do
    export "$setting"
done < /etc/environment
unset setting
