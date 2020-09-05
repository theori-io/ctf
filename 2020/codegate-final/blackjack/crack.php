<?php
class PlayingCard {
    public $suit;
    public $rank;
    public $val;
}
function genDeck($seed) {
    $s = array("C", "H", "D", "S");
    $r = array("A", "2", "3", "4", "5", "6", "7", "8", "9", "10", "J", "Q", "K");
    $deck = array();
    foreach($s as $suit) {
        foreach($r as $rank) {
            $c = new PlayingCard();
            $c->suit = $suit;
            $c->rank = $rank;
            if($rank === "A")
                $c->val = 1;
            else if($rank === "J" || $rank === "Q" || $rank === "K")
                $c->val = 10;
            else
                $c->val = intval($rank);
            $deck[] = $c;
        }
    }

    for($i=0; $i<(1<<16); $i++) {
        $x = $seed % 52;
        $y = ($seed + intval($seed / 17) + ($seed % 831)) % 52;
        $seed = pow($seed % 301, 5) + intval($seed / 41) + ((7 * $seed) % 101);
        $t = $deck[$x];
        $deck[$x] = $deck[$y];
        $deck[$y] = $t;
    }
    return $deck;
}

$seed = (int)$argv[1];
$ret = genDeck($seed);
foreach ($ret as $key) {
    echo $key->val.", ";
}
