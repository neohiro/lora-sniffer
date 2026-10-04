# The device list

A separate list of **nodes**, not a stream of frames and not a `grep` over the capture.
It has its own structure, its own command, and two orderings — and it lives on the
device *and* in `sniffctl.py`, so both work with the other side absent.

## Two orderings, because they answer different questions

| Order | Answers | For |
|---|---|---|
| `shortest-path` | "which nodes can I reach most directly?" | finding the interesting one |
| `last-seen` | "what just started talking?" | catching something appearing |
| `frames` | "who is loudest here?" | finding a chatty or misbehaving device |

**Shortest path first** is the default because hop count *is* distance on a flooding
mesh, and a repeater three hops away that you can also hear directly is worth more
attention than the one you can only hear through two other people.

**Last seen** exists because the default is wrong for a specific and common moment: a
node that starts talking a second ago sorts behind every device heard an hour ago and
disappears. That is exactly when you are watching.

Both are available over one table. The ordering is a property of the *accessor*, never of
the storage — nothing is ever re-sorted, because re-sorting on a microcontroller means
either an allocation or a hand-written insertion sort, and both are worse than choosing
an order when somebody asks for a list.

## Unknown distance sorts last

A frame with no path field is **not** a frame from a node next door. MeshCore adverts
carry no path; MeshCore group text carries a path length of zero because the sender does
not know it; LoRaWAN is a star topology where a gateway always hears its devices
directly.

So `Device` keeps `hopsValid` separate from `hops`, and `shortest-path` puts unknown
distance after every known distance. Putting it first would be the default-looking
answer, and it would be a lie — it would report every MeshCore node as adjacent.

```
0  MT deadbeef hops=0  rssi=  -95 name=roof-2      x14 2s ago
1  MT 1a2b3c4d hops=2  rssi= -101 x6  2s ago
2  MC 01020304 hops=?  rssi= -110 role=repeater name=mast-7 x3 1s ago
3  MC 05060708 hops=?  rssi= -112 x1  4s ago

4 nodes, shortest-path order, 1 direct, 2 within 3 hops, 2 with unknown distance
```

## Identity is a pair

Three protocols name nodes three ways, and the table holds all of them without
pretending they are the same thing:

| Protocol | Identifier | Identity kind |
|---|---|---|
| MeshCore | Ed25519 public key, 32 B | `meshcore-key` (leading 4 B) |
| Meshtastic | node number, 4 B | `meshtastic-node` |
| LoRaWAN | DevEUI 8 B, DevAddr 4 B | `lorawan-deveui`, `lorawan-devaddr` |

**Protocol and identity kind are part of the key**, so the same four bytes on two
protocols are two rows. Two communities sharing one frequency is the premise of the
hardware; a device list that merged them would be wrong about the most likely thing on
the band.

Four bytes, not thirty-two: MeshCore's own node hash is one byte, four is what fits this
table, and the full key stays in the frame that carried it and in the capture's hex.
That trade is made explicitly rather than by accident.

## What the list deliberately does not contain

**A MeshCore group text message names a channel, not a sender.** Nothing in the frame
says which node sent it, so no device entry is created and nothing is attributed to a
node. The text is retained against the entry for the channel so that "what has been said
on this channel" is answerable — without inventing a sender.

That is why a capture of pure group traffic produces an empty device list, and why the
empty case says so rather than printing nothing:

```
no nodes named themselves in this capture. A MeshCore advert or a Meshtastic header is
what puts a node on this list; a group text message does not, because the format does not
say who sent it.
```

## The best hearing of a node is kept

A node seen at −110 dBm and later at −95 keeps −95. A flood can reach you the long way
round, and a later, longer sighting must not push a node down the shortest-path list.
Both are `min`, not `last`, and both are tested.

## Eviction

Fixed capacity, no allocation. A new node takes a free slot; when there are none, the
node with the **oldest last-seen** is replaced.

LRU is the right policy for a specific reason: the node you have not heard from in the
longest time is the one you are least likely to be about to hear again, and evicting
anything else would drop a node that is still active.

The table is sized by the memory profile, not by ambition:

| Profile | Capacity |
|---|---:|
| `psram` | 256 |
| `standard` | 64 |
| `bare` | 32 |

`DeviceTable<N>` is a template precisely so it can live in static memory and
`sizeof` is exact — which is what lets `MemoryBudget` compute the working set at compile
time with no constant to forget. See [MEMORY.md](MEMORY.md).

## Using it

On the board:

```
devices                  shortest path, the default
devices last-seen
devices frames
devices 0                the first ten only
```

From a capture, with no hardware at all:

```bash
sniffctl --devices capture.jsonl
sniffctl --devices --order last-seen capture.jsonl
sniffctl --devices --order frames capture.jsonl
sniffctl --devices --limit 200 capture.jsonl
```

`sniffctl` rebuilds the same table from the capture, with the same identity rules, the
same unknown-distance handling and the same "best hearing wins". That is why a capture
taken on a roof three days ago can be interrogated tonight.

## A filter does not empty the list

`Console::observe()` updates the device list **before** consulting the filter.

A filter changes what is *shown*, not what was *heard*. A device list that emptied
because somebody typed `filter proto=mt` would be actively misleading — and the natural
next conclusion, "so nobody else is here", is exactly the wrong one.

This is asserted in `tests/test_pipeline.cpp`, because it is the kind of thing that looks
like an optimisation and is a bug.
