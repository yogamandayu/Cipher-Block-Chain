<?php
/**
 *
 */
class Cipher extends CI_Controller
{
  protected $key;
  protected $cipherText;
  protected $plainText;
  protected $binary_cipher = array(
  '0' => '1010010'
  );
  protected $indexbinary_cipher = 0;

  public function __construct()
  {
    parent::__construct();
    $this->load->helper('url');
    $this->load->library('session');
    $this->key = "d";
  }

  function encrypt($plainText){
    for ($i=0; $i < strlen($plainText) ; $i++) {
      $this->encrypt_operation($plainText{$i});
    }
    echo "Cipher Text : ".$this->cipherText;
  }

  function decrypt($cipherText){
    $this->indexbinary_cipher = strlen($cipherText)/2;
    for ($i=0; $i <strlen($cipherText)/2 ; $i++) {
      array_push($this->binary_cipher, $this->hex_to_bin(substr($cipherText,2*$i,2)));
    }
    for ($i=1; $i <=strlen($cipherText)/2 ; $i++) {
      $this->decrypt_operation(substr($cipherText,-2*$i,2)); #mengirim subcipher secara bertahap dengan pengiriman sebanyak 2 karakter, karena 2 karakter cipher = 1 plainteks
    }
    return strrev($this->plainText);
  }

  function encrypt_operation($subPlain){
    $p = $this->char_to_bin($subPlain);
    $k = $this->char_to_bin($this->key);
    $xorText = $this->xor_plain_binary_cipher($p);
    $binary_cipher = $this->xor_binary_cipher_key($k, $xorText);
    $new_binary_cipher = $this->shift_left($binary_cipher); #menggeser ke kiri hasil xor sebanyak satu kali
    array_push($this->binary_cipher,$new_binary_cipher); #menambahkan binary_cipher baru kedalam array binary_cipher, untuk dipakai pada saat decrypt
    $subCipher = $this->bin_to_hex($new_binary_cipher); #merubah hasil biner ke hexadecimal
    $this->cipherText .= $subCipher; #menambahkan subchiper kedalam array ciphertext
    $this->indexbinary_cipher++; #increment index dari indexbinary_cipher
  }

  function decrypt_operation($subCipher){
    $subBinCipher = $this->hex_to_bin($subCipher); #mengembalikan dari hexadecimal ke biner
    $new_binary_cipher = $this->shift_right($subBinCipher); #geser kekanan bit binary_cipher sebanyak 1 kali
    $k = $this->char_to_bin($this->key); #menambah bit key menjadi 7 bit, karena ada character yg kurang dari 7 bit
    $xorText = $this->xor_binary_cipher_shiftedkey($new_binary_cipher,$k);
    $plainText = $this->xor_plain_pre_binary_cipher($xorText);
    $this->indexbinary_cipher--; #indexbinary_cipher dikurang 1
    $this->plainText .= $this->bin_to_char($plainText);
  }

  function char_to_bin($char){
    return sprintf("%07d", decbin(ord($char))); #ord merubah subplain menjadi ASCII - decbin merubah ASCII menjadi biner 7-bit
  }                                             #menambah bit key menjadi 7 bit, karena ada character yg kurang dari 7 bit
 
  function bin_to_char($bin){
    return chr(bindec($bin));                    #bindec merubah hasil geser xor kedalam ASCII - chr merubah ASCII ke dalam character
  }                                             #merubah plaintext dari biner -> ASCII -> character kemudian disimpan dalam array plaintext

  function xor_plain_binary_cipher($p){
    $xorText = "";
    for ($i=0; $i < 7 ; $i++) { #xor subplaintext dengan binary_cipher ke- $indexbinary_cipher
      if($p{$i} xor $this->binary_cipher[$this->indexbinary_cipher]{$i}){
        $xorText .= "1";
      }
      else {
        $xorText .= "0";
      }
    }
    return $xorText;
  }

  function bin_to_hex($bin){
    $bin8 = sprintf("%08d", $bin); #biner yg dikirim diubah menjadi format 8 bit
    $subHex="";
    for ($i=0; $i < strlen($bin8) ; $i+=4) {
      $subBin = substr($bin8,$i,4); #8 bit tadi di bagi menjadi 2, yaitu 4 bit 4 bit agar hasil hexadecimal hanya satu karakter, jadi setiap 1 plaintext akan menjadi 2 bilangan hex
      $subHex .= $this->oct_to_hex($this->bin_to_oct($subBin));
    }
    return $subHex;
  }

  function hex_to_bin($hex){
    $bin = "";
    for ($i=0; $i < 2; $i++) {
      $bin .= sprintf("%04d", $this->oct_to_bin($this->hex_to_oct($hex{$i}))); #karena 2 bilangan hex = 1 karakter plaintext, maka 2 hex tersebut dirubah jadi biner
    }                                                                          #dan digabungkan, setelah itu, dirubah kembali menjadi 7 bit dengan mengambil angka pertama.
    $bin = substr($bin,1);
    return $bin;
  }

  function bin_to_oct($bin){ #merubah biner jadi octal
    return base_convert($bin,2,8);
  }

  function oct_to_bin($oct){ #merubah octal jadi biner
    return base_convert($oct,8,2);
  }

  function oct_to_hex($oct){ #merubah octal jadi hexadecimal
    return base_convert($oct,8,16);
  }

  function hex_to_oct($hex){ #merubah hexadecimal jadi octal
    return base_convert($hex,16,8);
  }

  function xor_binary_cipher_key($k, $xorText){
    $binary_cipher = "";
    for ($i=0; $i < 7 ; $i++) { #xor hasil xor sebelumnya dengan key
      if($k{$i} xor $xorText{$i}){
        $binary_cipher .= "1";
      }
      else {
        $binary_cipher .= "0";
      }
    }
    return $binary_cipher;
  }

  function xor_binary_cipher_shiftedkey($new_binary_cipher,$k){
    $xorText = "";
    for ($i=0; $i < 7 ; $i++) {
      if($new_binary_cipher{$i} xor $k{$i}){ #xor kan binary_cipher yg telah digeser dengan key
        $xorText .= "1";
      }
      else {
        $xorText .= "0";
      }
    }
    return $xorText;
  }

  function xor_plain_pre_binary_cipher($xorText){
    $plainText = "";
    for ($i=0; $i < 7 ; $i++) {
      if($xorText{$i} xor $this->binary_cipher[$this->indexbinary_cipher-1]{$i}){ #xor hasil xor sebelumnya dengan binary_cipher pada index sebelumnya
        $plainText .= "1";
      }
      else {
        $plainText .= "0";
      }
    }
    return $plainText;
  }

  function shift_left($xorText){
    $begin = $xorText{0}; #ambil karakter pertama pada string
    $new_xor = substr($xorText,1); #ambil string setelah karakter pertama
    return $new_xor.= $begin; #memindahkan karakter pertama ke index ke 6, yaitu akhir string
  }

  function shift_right($xorText){
    $begin = $xorText{6}; #ambil karakter di index ke 6 atau karakter terakhir
    return substr_replace($xorText, $begin, 0, 0); #memindahkan karakter terakhir ke index ke 0 atau karakter pertama
  }
}


 ?>
