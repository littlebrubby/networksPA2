# Copyright 2013 <Your Name Here>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
A skeleton POX component

You can customize this to do whatever you like.  Don't forget to
adjust the Copyright above, and to delete the Apache license if you
don't want to release under Apache (but consider doing so!).

Rename this file to whatever you like, .e.g., mycomponent.py.  You can
then invoke it with "./pox.py mycomponent" if you leave it in the
ext/ directory.

Implement a launch() function (as shown below) which accepts commandline
arguments and starts off your component (e.g., by listening to events).

Edit this docstring and your launch function's docstring.  These will
show up when used with the help component ("./pox.py help --mycomponent").
"""

# Import some POX stuff
from pox.core import core                     # Main POX object
import pox.openflow.libopenflow_01 as of      # OpenFlow 1.0 library
import pox.lib.packet as pkt                  # Packet parsing/construction
from pox.lib.addresses import EthAddr, IPAddr # Address types
import pox.lib.util as poxutil                # Various util functions
import pox.lib.revent as revent               # Event library
import pox.lib.recoco as recoco               # Multitasking library
from pox.lib.packet.arp import arp
from pox.lib.packet.ethernet import ethernet, ETHER_BROADCAST
from pox.lib.packet.vlan import vlan
from pox.lib.util import dpid_to_str, str_to_bool
# Create a logger for this component
log = core.getLogger()


class BalanceSwitch (object):
  def __init__(self, connection):
    self.connection = connection
    self.next_host = 5
    core.openflow.addListeners(self)
    core.addListeners(self)

  #def _handle_GoingUpEvent(self, event):
    #core.openflow.addListeners(self)

  def _handle_PacketIn(self, event):
    log.info("packet received")
    dpid = event.connection.dpid
    inport = event.port
    packet = event.parsed
    if not packet.parsed:
      log.warning("%s: ignoring unparsed packet", dpid_to_str(dpid))
      return

    a = packet.find('arp')
    if a is not None:
      log.debug("%s ARP %s %s => %s", dpid_to_str(dpid),
        {arp.REQUEST: "request", arp.REPLY: "reply"}.get(a.opcode,
        'op:%i' % (a.opcode,)), str(a.protosrc),str(a.protodst))

      if a.prototype == arp.PROTO_TYPE_IP:
        if a.hwtype == arp.HW_TYPE_ETHERNET:
          if a.protosrc != 0:
            if a.opcode == arp.REQUEST:
              msg = of.ofp_flow_mod()
              msg.priority = 42
              msg.match.in_port = inport
              msg.match.dl_type = 0x800
              msg.match.nw_dst = IPAddr("10.0.0.10")
              msg.actions.append(of.ofp_action_output(port=self.next_host))
              self.connection.send(msg)

              msg = of.ofp_flow_mod()
              msg.priority = 42
              msg.match.in_port = self.next_host
              msg.match.dl_type = 0x800
              msg.match.nw_dst = a.src
              msg.actions.append(of.ofp_action_output(inport))
              self.connection.send(msg)

              # switch to next host
              if self.next_host == 5:
                self.next_host = 6
              else:
                self.next_host = 5

              r = arp()
              r.hwtype = a.hwtype
              r.prototype = a.prototype
              r.hwlen = a.hwlen
              r.protolen = a.protolen
              r.opcode = arp.REPLY
              r.hwdst = a.hwsrc
              r.hwsrc = IPAddr("10.0.0." + str(self.next_host))
              r.protodst = a.protosrc
              r.protosrc = a.protodst

              e = ethernet(type=packet.type, src=event.connection.eth_addr,
                           dst=a.hwsrc)
              e.payload = r
              if packet.type == ethernet.VLAN_TYPE:
                v_rcv = packet.find('vlan')
                e.payload = vlan(eth_type=e.type,
                                 payload=e.payload,
                                 id=v_rcv.id,
                                 pcp=v_rcv.pcp)
                e.type = ethernet.VLAN_TYPE
              log.info("%s answering ARP for %s" % (dpid_to_str(dpid),
                                                    str(r.protosrc)))
              msg = of.ofp_packet_out()
              msg.data = e.pack()
              msg.in_port = inport
              msg.actions.append(of.ofp_action_output(port=
                                                      of.OFPP_IN_PORT))

              event.connection.send(msg)



class StartUp(object):
  """
  Waits for a switch to connect and makes it a BalanceSwitch (giving connection to itself as param)
  """

  def __init__(self):
    """
    Initialize
    """
    core.openflow.addListeners(self)

  def _handle_ConnectionUp(self, event):
    log.info("Connection %s" % (event.connection,))
    BalanceSwitch(event.connection)

@poxutil.eval_args
def launch ():
  log.info("hello")
  """
  The default launcher just logs its arguments
  """
  # When your component is specified on the commandline, POX automatically
  # calls this function.

  # Add whatever parameters you want to this.  They will become
  # commandline arguments.  You can specify default values or not.
  # In this example, foo is required and bar is not.  You may also
  # specify a keyword arguments catch-all (e.g., **kwargs).

  # For example, you can execute this component as:
  # ./pox.py skeleton --foo=3 --bar=4

  # Note that arguments passed from the commandline are ordinarily
  # always strings, and it's up to you to validate and convert them.
  # The one exception is if a user specifies the parameter name but no
  # value (e.g., just "--foo").  In this case, it receives the actual
  # Python value True.
  # The @pox.util.eval_args decorator interprets them as if they are
  # Python literals.  Even things like --foo=[1,2,3] behave as expected.
  # Things that don't appear to be Python literals are left as strings.

  # If you want to be able to invoke the component multiple times, add
  # __INSTANCE__=None as the last parameter.  When multiply-invoked, it
  # will be passed a tuple with the following:
  # 1. The number of this instance (0...n-1)
  # 2. The total number of instances for this module
  # 3. True if this is the last instance, False otherwise
  # The last is just a comparison between #1 and #2, but is convenient.

  core.registerNew(StartUp)
