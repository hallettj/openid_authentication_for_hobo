module Hobo

  module OpenidUserController

    class << self
      def included(base)
        base.skip_before_filter :login_required, :only => [:login, :complete]
        Hobo::UserController.user_models << base.model
      end
    end
    
    def login; hobo_login; end
    def complete; hobo_complete; end

    def logout; hobo_logout; end
    
    def hobo_login(options={})
      @user_model = model

      options = LazyHash.new(options)
      options.reverse_merge!(:lookup_failure_notice => "Could not locate OpenID server.",
                             :return_to => url_for(:action => :complete))
      
      if request.post?
        openid = params[:login]
        request = openid_consumer.begin openid

        case request.status
        when OpenID::SUCCESS
          return_to = options[:return_to]
          trust_root = homepage_url
          
          # If this is going to be a new account...
          unless model.find_by_identity_url(OpenID::Util.normalize_url(openid))
            required_sreg_keys =
              model.simple_registration_mappings[:required] ?
                model.simple_registration_mappings[:required].keys.join(",") : nil
            optional_sreg_keys =
              model.simple_registration_mappings[:optional] ?
                model.simple_registration_mappings[:optional].keys.join(",") : nil

            unless required_sreg_keys.blank?
              request.add_extension_arg('sreg', 'required', required_sreg_keys)
            end
            unless optional_sreg_keys.blank?
              request.add_extension_arg('sreg', 'optional', optional_sreg_keys)
            end
            if !options[:policy_url].blank?
              request.add_extension_arg('sreg', 'policy_url', options[:policy_url])
            elsif defined_route?("policy")
              request.add_extension_arg('sreg', 'policy_url', policy_url)
            end
            
            # sreg modes: required, optional, policy_url
            # sreg params: policy_url, email, nickname, fullname, dob,
            # gender, postcode, country, timezone, language

          end
          
          redirect_to request.redirect_url trust_root, return_to
          return

        when OpenID::FAILURE
          flash[:notice] = options[:lookup_failure_notice]
        else
          flash[:notice] = "An unknown error occurred."
        end
      end

      hobo_render unless performed?
    end

    def hobo_complete(options={})
      @user_model = model

      options = LazyHash.new(options)
      options.reverse_merge!(:success_notice => "You have logged in",
                             :failure_notice => "Verification failed",
                             :cancellation_notice => "Verification cancelled",
                             :setup_needed_notice => "OpenID server reports setup is needed",
                             :new_user_failure_notice => "Could not create a new user account",
                             :redirect_to => { :action => "index" })

      user = nil
      response = openid_consumer.complete params

      case response.status
      when OpenID::SUCCESS
        openid = response.identity_url
        user = model.find_by_identity_url(openid)
        
        ## If a user account doesn't exist yet, then create one
        if user.nil?
          
          # Generate parameters for new user record
          user_attrs = { model.login_attr => openid }

          sreg = response.extension_response('sreg')
          model.simple_registration_mappings.each do |set,mappings|
            mappings.each do |key,col|
              user_attrs[col] = sreg[key.to_s]
            end
          end
          
          user = model.new(user_attrs)

          unless user.save!
            flash[:notice] = options[:new_user_failure_notice]
            user = nil
          end
          
        end
        
      when OpenID::FAILURE
        flash[:notice] = options[:failure_notice]
        
      when OpenID::CANCEL
        flash[:notice] = options[:cancellation_notice]

      when OpenID::SETUP_NEEDED
        flash[:notice] = options[:setup_needed_notice]

      else
        flash[:notice] = "Unknown response from OpenID server."
      end

      if user.nil?
        flash[:notice] ||= options[:failure_notice]
      else
        old_user = current_user
        self.current_user = user
        
        # If supplied, a block can be used to test if this user is
        # allowed to log in (e.g. the account may be disabled)
        if block_given? && !yield
          # block returned false - cancel this login
          self.current_user = old_user
        else
          if params[:remember_me] == "1"
            current_user.remember_me
            create_auth_cookie
          end
          flash[:notice] ||= options[:success_notice]
          unless performed?
            redirect_back_or_default(options[:redirect_to] || 
                                     url_for(:controller => "front",
                                             :action => "index"))
          end
        end
      end
      redirect_to :action => "login" unless performed?
    end
    
    def hobo_logout(options={})
      options = options.reverse_merge(:notice => "You have been logged out.",
                                      :redirect_to => {:action => "index"})
        
      current_user.forget_me if logged_in?
      cookies.delete :auth_token
      reset_session
      flash[:notice] = options[:notice]
      redirect_back_or_default(options[:redirect_to])
    end

    private
    
    # Get the OpenID::Consumer object.
    def openid_consumer
      # create the OpenID store for storing associations and nonces,
      # putting it in your app's db directory
      # you can also use database store.
      store_dir = Pathname.new(RAILS_ROOT).join('db').join('openid-store')
      store = OpenID::FilesystemStore.new(store_dir)
      
      return OpenID::Consumer.new(session, store)
    end
    
  end
  
end
