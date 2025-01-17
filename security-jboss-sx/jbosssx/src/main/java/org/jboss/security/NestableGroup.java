/*
* JBoss, Home of Professional Open Source
* Copyright 2005, JBoss Inc., and individual contributors as indicated
* by the @authors tag. See the copyright.txt in the distribution for a
* full listing of individual contributors.
*
* This is free software; you can redistribute it and/or modify it
* under the terms of the GNU Lesser General Public License as
* published by the Free Software Foundation; either version 2.1 of
* the License, or (at your option) any later version.
*
* This software is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
* Lesser General Public License for more details.
*
* You should have received a copy of the GNU Lesser General Public
* License along with this software; if not, write to the Free
* Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
* 02110-1301 USA, or see the FSF site: http://www.fsf.org.
*/
package org.jboss.security;

import java.security.Principal;
import org.apache.cxf.common.security.GroupPrincipal;
import org.apache.cxf.common.security.SimplePrincipal;

import java.util.Enumeration;
import java.util.LinkedList;

//$Id$

/** An implementation of GroupPrincipal that allows that acts as a stack of Groups
with a single GroupPrincipal member active at any time.
When one adds a GroupPrincipal to a NestableGroup the GroupPrincipal is pushed onto
the active GroupPrincipal stack and any of the GroupPrincipal methods operate as though the
NestableGroup contains only the Group. When removing the GroupPrincipal that
corresponds to the active Group, the active GroupPrincipal is popped from the stack and
the new active GroupPrincipal is set to the new top of the stack.

The typical usage of this class is when doing a JAAS LoginContext login
to runAs a new Principal with a new set of roles that should be added
without destroying the current identity and roles.

@author  Scott.Stark@jboss.org
@version $Revision$
*/
public class NestableGroup extends SimplePrincipal implements GroupPrincipal, Cloneable
{
    /** The serialVersionUID */
   private static final long serialVersionUID = 1752783303935807441L;
   /** The stack of the Groups. Elements are pushed/poped by
        inserting/removing element 0.
    */
    private LinkedList<Principal> rolesStack;

    /** Creates new NestableGroup with the given name
    */
    public NestableGroup(String name)
    {
        super(name);
        rolesStack = new LinkedList<Principal>();
    }

// --- Begin GroupPrincipal interface methods
    /** Returns an enumeration that contains the single active Principal.
    @return an Enumeration of the single active Principal.
    */
    public Enumeration<Principal> members()
    {
        return new IndexEnumeration<Principal>();
    }

    /** Removes the first occurence of user from the Principal stack.

    @param user the principal to remove from this group.
    @return true if the principal was removed, or
     * false if the principal was not a member.
    */
    public boolean removeMember(Principal user)
    {
        return rolesStack.remove(user);
    }

    /** Pushes the GroupPrincipal onto the GroupPrincipal stack and makes it the active
        Group.
    @param GroupPrincipal the instance of GroupPrincipal that contains the roles to set as the
        active Group.
    @exception IllegalArgumentException thrown if GroupPrincipal is not an instance of Group.
    @return true always.
    */
    public boolean addMember(Principal group) throws IllegalArgumentException
    {
        if( (group instanceof GroupPrincipal) == false )
            throw PicketBoxMessages.MESSAGES.invalidType(GroupPrincipal.class.getName());

        rolesStack.addFirst(group);
        return true;
    }

    /** Returns true if the passed principal is a member of the active group.
        This method does a recursive search, so if a principal belongs to a
        GroupPrincipal which is a member of this group, true is returned.

     @param member the principal whose membership is to be checked.

     @return true if the principal is a member of this group, false otherwise.
    */
    public boolean isMember(Principal member)
    {
        if( rolesStack.size() == 0 )
            return false;
        GroupPrincipal activeGroup = (GroupPrincipal) rolesStack.getFirst();
        boolean isMember = activeGroup.isMember(member);
        return isMember;
    }

   public String toString()
   {
      StringBuffer tmp = new StringBuffer(getName());
      tmp.append("(members:");
      Enumeration<Principal> iter = members();
      while( iter.hasMoreElements() )
      {
         tmp.append(iter.nextElement());
         tmp.append(',');
      }
      tmp.setCharAt(tmp.length()-1, ')');
      return tmp.toString();
   }

   @SuppressWarnings("unchecked")
   public synchronized Object clone() throws CloneNotSupportedException
   {
      NestableGroup clone = (NestableGroup) super.clone();
      if(clone != null)
        clone.rolesStack = (LinkedList<Principal>)this.rolesStack.clone();
      return clone;
   }

// --- End GroupPrincipal interface methods

    private class IndexEnumeration<T extends Principal> implements Enumeration<Principal>
    {
        private Enumeration<? extends Principal> iter;

        IndexEnumeration()
        {
            if( rolesStack.size() > 0 )
            {
                GroupPrincipal grp = (GroupPrincipal) rolesStack.get(0);
                iter = grp.members();
            }
        }
        public boolean hasMoreElements()
        {
            boolean hasMore = iter != null && iter.hasMoreElements();
            return hasMore;
        }
        public Principal nextElement()
        {
            Principal next = null;
            if( iter != null )
                next = iter.nextElement();
            return next;
        }
    }
}