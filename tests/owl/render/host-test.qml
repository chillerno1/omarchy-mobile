// SPDX-License-Identifier: MIT
import QtQuick
import Quickshell
import Quickshell.Io
import "home" as Home
import "home/owl" as Owl

// The phone host and the live widget with mocks, in the container: haptics
// and the torch only behind their approval (argv captured, nothing runs),
// stream lines, a watched file, a terminal session, a widget's screen.
// Prints TAP lines and exits 1 on a failure.
ShellRoot {
  id: t
  property int failures: 0
  property var executed: []
  function check(name, ok, detail) {
    console.log((ok ? "ok - " : "not ok - ") + name + (ok || !detail ? "" : " (" + detail + ")"))
    if (!ok) t.failures++
  }
  function mockWidget(key, approval) {
    return { stateKey: key, approval: approval, problems: [], reported: [],
             report: function(m) { this.reported.push(m) }, refreshSoon: function() {} }
  }

  Home.OwlPhoneHost {
    id: host
    execute: function(argv) { t.executed = t.executed.concat([argv]) }
  }

  property var lines: []
  property var fileTexts: []
  property string termOut: ""
  property bool termEnded: false
  property var streamHandle: null

  Owl.OwlWidget {
    id: screenWidget
    stateKey: ""
    host: ({ loadState: function() { return {} }, saveState: function() {}, report: function() {}, interval: function(s) { return s.every },
             runSource: function() {}, android: function() {}, act: function() {}, runInto: function() {},
             stream: function(w, spec, arg, onLine) { onLine("first"); t.pushLater = onLine; return { stop: function() { t.stopped = true } } },
             watch: function() { return null } })
    text: 'widget "w" {\n  meta { owl: 5 }\n  source s = stream("tail -f x")\n  onTap: screen()\n  Text { text: "tile ${s}" }\n  screen {\n    title: "more"\n    Text { text: "big ${s}" }\n  }\n}\n'
    active: true
  }
  property var pushLater: null
  property bool stopped: false

  Component.onCompleted: {
    const plain = t.mockWidget("a@1", null)
    host.act(plain, "haptic", [])
    t.check("haptic without approval does nothing", t.executed.length === 0 && plain.reported.length === 1, JSON.stringify(t.executed))
    const allowed = t.mockWidget("b@1", { commands: [], devices: ["haptic", "torch"] })
    host.act(allowed, "haptic", [])
    t.check("haptic with approval asks feedbackd", JSON.stringify(t.executed[0]) === JSON.stringify(["fbcli", "-E", "button-pressed"]), JSON.stringify(t.executed))
    const torchOnly = t.mockWidget("c@1", { commands: [], devices: ["torch"] })
    host.act(torchOnly, "torch", [true])
    t.check("torch with approval sets the LED", t.executed.length === 2 && JSON.stringify(t.executed[1]) === JSON.stringify(["omamobile-torch", "on"]), JSON.stringify(t.executed))
    host.act(torchOnly, "torch", [false])
    t.check("a second action within a second is held back", t.executed.length === 2 && torchOnly.reported.length === 1)

    const sw = t.mockWidget("d@1", { commands: [], network: false })
    t.streamHandle = host.stream(sw, { name: "s" }, "for i in 1 2 3; do echo line$i; sleep 0.1; done; sleep 30", function(l) { t.lines = t.lines.concat([l]) })
    writer.running = true
    t.term = host.terminalFor(sw).start("echo hi-from-pty", function(c) { t.termOut += c }, function() { t.termEnded = true })
    later.start()
  }
  property var term: null

  Process { id: writer; command: ["sh", "-c", "printf a > /tmp/owl-watch.txt"]; onExited: {
    t.watchHandle = host.watch(t.mockWidget("e@1", null), { name: "f" }, "/tmp/owl-watch.txt", function(x) { t.fileTexts = t.fileTexts.concat([x]) })
    changer.running = true
  } }
  property var watchHandle: null
  Process { id: changer; command: ["sh", "-c", "sleep 0.5; printf b > /tmp/owl-watch.txt"] }

  Timer {
    id: later
    interval: 2500
    onTriggered: {
      t.check("a stream gives one value per line", t.lines.join(",") === "line1,line2,line3", t.lines.join(","))
      t.streamHandle.stop()
      t.check("a stream stops", host.streamCount === 0, host.streamCount)
      t.check("a watched file is read, and again when it changes", t.fileTexts[0] === "a" && t.fileTexts[t.fileTexts.length - 1] === "b", JSON.stringify(t.fileTexts))
      t.watchHandle.stop()
      t.check("a terminal session shows its output and ends", t.termOut.indexOf("hi-from-pty") >= 0 && t.termEnded, JSON.stringify(t.termOut))
      t.check("a stream source updates the tile", !!screenWidget.tree && screenWidget.tree.children[0].p.text === "tile first", screenWidget.tree ? screenWidget.tree.children[0].p.text : "no tree")
      t.pushLater("second")
      Qt.callLater(function() {
        t.check("each line is a new value", screenWidget.tree.children[0].p.text === "tile second")
        screenWidget.act("screen", [])
        t.check("screen() opens the widget's screen", screenWidget.screenOpen && screenWidget.screenTree.title === "more" && screenWidget.screenTree.children[0].p.text === "big second")
        screenWidget.act("close", [])
        t.check("close() goes back to the tile", !screenWidget.screenOpen)
        screenWidget.active = false
        Qt.callLater(function() {
          t.check("a hidden widget stops its stream", t.stopped)
          Qt.exit(t.failures ? 1 : 0)
        })
      })
    }
  }
}
