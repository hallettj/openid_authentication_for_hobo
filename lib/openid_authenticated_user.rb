module Hobo

  module OpenidAuthenticatedUser

    # Extend the base class with AuthenticatedUser functionality
    # This includes:
    # - plaintext password during login and encrypted password in the database
    # - plaintext password validation
    # - login token for rembering a login during multiple browser sessions
    def self.included(base)
      base.extend(ClassMethods)

      base.class_eval do
        fields do
          remember_token            :string
          remember_token_expires_at :datetime
        end
        
        never_show :remember_token, :remember_token_expires_at
      end
    end

    # Additional classmethods for AuthenticatedUser
    module ClassMethods
      
      def set_login_attr(attr)
        @login_attr = attr = attr.to_sym
        alias_attribute(:login, attr) unless attr == :login
        
        if block_given?
          yield
        else 
          validates_presence_of   attr
          validates_length_of     attr, :within => 3..100
          validates_uniqueness_of attr, :case_sensitive => false
        end
      end
      def login_attr; @login_attr; end

      def set_simple_registration_mappings(mappings=nil)
        if block_given?
          mappings = yield
        end
        if @sreg_mappings.blank?
          @sreg_mappings = mappings
        else
          @sreg_mappings.merge!(mappings || {})
        end
      end
      def simple_registration_mappings; @sreg_mappings; end

      def find_by_identity_url(url)
        find(:first, :conditions => ["#{@login_attr} = ?", url])
      end

      # Authenticates a user by their login name and unencrypted password.  Returns the user or nil.
#       def authenticate(login, password)
#         u = find(:first, :conditions => ["#{@login_attr} = ?", login]) # need to get the salt
        
#         if u && u.authenticated?(password)
#           if u.respond_to?(:last_login_at) || u.respond_to?(:logins_count)
#             u.last_login_at = Time.now if u.respond_to?(:last_login_at)
#             u.logins_count = (u.logins_count.to_i + 1) if u.respond_to?(:logins_count)
#             u.save
#           end
#           u
#         else
#           nil
#         end
#       end

    end

    # Check if the encrypted passwords match
#     def authenticated?(password)
#       crypted_password == encrypt(password)
#     end

    # Do we still need to remember the login token, or has it expired?
    def remember_token?
      remember_token_expires_at && Time.now.utc < remember_token_expires_at
    end

    # These create and unset the fields required for remembering users between browser closes
    def remember_me
      self.remember_token_expires_at = 2.weeks.from_now.utc
      self.remember_token            = encrypt("#{login}--#{remember_token_expires_at}")
      save(false)
    end

    # Expire the login token, resulting in a forced login next time.
    def forget_me
      self.remember_token_expires_at = nil
      self.remember_token            = nil
      save(false)
    end

    def guest?
      false
    end
    
  end

end
