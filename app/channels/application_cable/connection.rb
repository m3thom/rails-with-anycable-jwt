module ApplicationCable
  class Connection < ActionCable::Connection::Base
    identified_by :current_user

    def connect
      self.current_user = find_verified_user
    end

    private

    def find_verified_user
      begin
        token = request.query_parameters["token"]
        # {"sub"=>"2", "scp"=>"user", "aud"=>nil, "iat"=>1655366190, "exp"=>1655625390, "jti"=>"123-some-jti"}
        payload = Warden::JWTAuth::TokenDecoder.new.call(token)

        Warden::JWTAuth::UserDecoder.new.call(token,
                                              payload["scp"].to_sym,
                                              payload["aud"])


      rescue => e
        Rails.logger.info e
        reject_unauthorized_connection
      end
    end
  end
end
