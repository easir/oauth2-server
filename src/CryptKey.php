<?php
/**
 * Cryptography key holder.
 *
 * @author      Julián Gutiérrez <juliangut@gmail.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/thephpleague/oauth2-server
 */

namespace League\OAuth2\Server;

use Exception;

class CryptKey
{
    const RSA_KEY_PATTERN =
        '/^(-----BEGIN (RSA )?(PUBLIC|PRIVATE) KEY-----\n)(.|\n)+(-----END (RSA )?(PUBLIC|PRIVATE) KEY-----)$/';

    /**
     * @var string
     */
    protected $keyPath;

    /**
     * @var null|string
     */
    protected $passPhrase;

    /**
     * @param string      $keyPath
     * @param null|string $passPhrase
     * @throws Exception
     */
    public function __construct($keyPath, $passPhrase = null)
    {
        if (preg_match(self::RSA_KEY_PATTERN, $keyPath)) {
            $keyPath = $this->saveKeyToFile($keyPath);
        }

        if (strpos($keyPath, 'file://') !== 0) {
            $keyPath = 'file://' . $keyPath;
        }

        if (!file_exists($keyPath) || !is_readable($keyPath)) {
            throw new \LogicException(sprintf('Key path "%s" does not exist or is not readable', $keyPath));
        }

        $this->keyPath = $keyPath;
        $this->passPhrase = $passPhrase;
    }

    /**
     * @param string $key
     * @throws Exception
     * @return string
     */
    private function saveKeyToFile($key)
    {
        $keyPath = sprintf('%s/%s.key', sys_get_temp_dir(), sha1($key));

        $handle = null;

        try {
            if (!is_file($keyPath) || filesize($keyPath) === 0) {
                $handle = fopen($keyPath, 'w+');
                $ret = flock($handle, LOCK_EX);
                if (!$ret) {
                    throw new Exception(sprintf('Could not acquire lockfile %s!', $keyPath));
                }
                //recheck if file is empty (maybe have  already been written by another process!)
                if (filesize($keyPath) === 0) {
                    file_put_contents($keyPath, $key);
                }
            }
        } catch (Exception $e) {
            throw new Exception(sprintf('Could not write key to %s!', $keyPath));
        } finally {
            if (is_resource($handle)) {
                flock($handle, LOCK_UN);
            }
        }

        return 'file://' . $keyPath;
    }

    /**
     * Retrieve key path.
     *
     * @return string
     */
    public function getKeyPath()
    {
        return $this->keyPath;
    }

    /**
     * Retrieve key pass phrase.
     *
     * @return null|string
     */
    public function getPassPhrase()
    {
        return $this->passPhrase;
    }
}
