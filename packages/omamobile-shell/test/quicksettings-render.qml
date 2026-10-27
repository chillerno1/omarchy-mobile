// SPDX-License-Identifier: MIT
import QtQuick
import Quickshell
import Quickshell.Io
import qs.Commons
import qs.Commons as Commons
import "quicksettings" as QS

// Offscreen review shots of quick settings (test/quicksettings-render):
// the real QuickSettings.qml at the phone's 480x1040 logical px and on
// its side at 1040x480, over an app stand-in, each shot in $QS_JOB
// (collapsed, expanded, editing, the reminder page) saved as a PNG with
// the geometry of the sheet, the tiles, the handle, the shade and the
// page's parts printed for the checks. Then it quits.
ShellRoot {
  id: shell

  FileView { id: jobFile; path: Quickshell.env("QS_JOB"); blockLoading: true }
  readonly property var job: JSON.parse(jobFile.text())
  property int index: -1
  readonly property var shot: shell.index >= 0 && shell.index < shell.job.shots.length ? shell.job.shots[shell.index] : null

  FloatingWindow {
    id: win
    implicitWidth: 1040
    implicitHeight: 1040
    color: "black"

    Item {
      id: screen
      width: shell.shot ? shell.shot.w : 480
      height: shell.shot ? shell.shot.h : 1040

      // An app behind the sheet: a bar and a dark window.
      Rectangle { width: parent.width; height: 44; color: Commons.Color.bar.background
        Text { x: 16; anchors.verticalCenter: parent.verticalCenter; text: "13:27"; color: Commons.Color.bar.text; font.family: Style.font.family; font.pixelSize: 15 } }
      Rectangle { y: 44; width: parent.width; height: parent.height - 44; color: "#202020"
        Text { anchors.centerIn: parent; text: "app"; color: "#808080"; font.pixelSize: 30 } }

      QS.QuickSettings {
        id: qs
        anchors.fill: parent
        // The pages (Wi-Fi, Bluetooth, record, reminder) are windows of
        // their own on the phone; their stand-ins fill the screen here.
        Component.onCompleted: {
          for (var i = 0; i < qs.children.length; i++) {
            var page = qs.children[i]
            if (page.opened === undefined || page.backRequested === undefined) continue
            page.width = Qt.binding(function() { return qs.width })
            page.height = Qt.binding(function() { return qs.height })
          }
        }
      }
    }
  }

  function rectOf(item) {
    var p = item.mapToItem(screen, 0, 0)
    return { x: Math.round(p.x), y: Math.round(p.y), w: Math.round(item.width), h: Math.round(item.height) }
  }

  // The named parts that are shown, as {name: {x, y, w, h}} in screen px.
  function describe(item, out) {
    if (!item || !item.visible || item.opacity === 0) return out
    if (item.objectName) out[item.objectName] = shell.rectOf(item)
    for (var i = 0; i < item.children.length; i++) shell.describe(item.children[i], out)
    return out
  }

  function next() {
    shell.index++
    if (shell.index >= shell.job.shots.length) { Qt.quit(); return }
    var s = shell.shot
    qs.close()
    Qt.callLater(function() {
      qs.open(JSON.stringify({ expanded: s.expanded === true, page: s.edit ? "edit" : (s.page || "") }))
      settle.restart()
    })
  }

  Timer { id: settle; interval: 1500; onTriggered: shell.capture() }

  function capture() {
    var s = shell.shot
    var parts = shell.describe(qs, {})
    console.log("geometry " + s.name + " " + screen.width + "x" + screen.height
                + " " + JSON.stringify({ parts: parts, columns: qs.tileColumns, expanded: qs.expanded, edit: qs.editing, page: s.page || "", notifications: qs.notifications.length }))
    screen.grabToImage(function(result) {
      result.saveToFile(s.png)
      console.log("shot " + s.png)
      Qt.callLater(shell.next)
    })
  }

  Timer { interval: 800; running: true; onTriggered: shell.next() }
}
