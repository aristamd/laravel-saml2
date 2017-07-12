<?php

namespace Aacotroneo\Saml2\Http\Controllers;

use Aacotroneo\Saml2\Events\Saml2LoginEvent;
use Aacotroneo\Saml2\Saml2Auth;
use Illuminate\Routing\Controller;
use Illuminate\Http\Request;
use HL7, Auth;
use App\Models\User;
use App\Exceptions\HL7\{InvalidMessageHL7Exception,InvalidHL7SegmentException, MissingHL7OrganizationException,
    MissingHL7SpecialtyException, MissingHL7ChiefComplaintException, MissingHL7WorkupChecklistException};
use App\Exceptions\AccessExceptions\PermissionDeniedException;


class Saml2Controller extends Controller
{

    protected $saml2Auth;

    /**
     * @param Saml2Auth $saml2Auth injected.
     */
    function __construct(Saml2Auth $saml2Auth)
    {
        $this->saml2Auth = $saml2Auth;
    }


    /**
     * Generate local sp metadata
     * @return \Illuminate\Http\Response
     */
    public function metadata()
    {

        $metadata = $this->saml2Auth->getMetadata();

        return response($metadata, 200, ['Content-Type' => 'text/xml']);
    }

    /**
     * Process an incoming saml2 assertion request.
     * Fires 'Saml2LoginEvent' event if a valid user is Found
     */
    public function acs()
    {
        $errors = $this->saml2Auth->acs();

        if (!empty($errors)) {
            logger()->error('Saml2 error_detail', ['error' => $this->saml2Auth->getLastErrorReason()]);
            session()->flash('saml2_error_detail', [$this->saml2Auth->getLastErrorReason()]);

            logger()->error('Saml2 error', $errors);
            session()->flash('saml2_error', $errors);
            return redirect(config('saml2_settings.errorRoute'));
        }

        $user = $this->getUser();
        event(new Saml2LoginEvent($user));

        $redirectUrl = $user->getIntendedUrl();

        if ($redirectUrl === null) {
            $redirectUrl = config('saml2_settings.loginRoute');
        }

        return $this->processRequestMessage( $user, $redirectUrl );
    }

    /**
     * Process an incoming saml2 logout request.
     * Fires 'saml2.logoutRequestReceived' event if its valid.
     * This means the user logged out of the SSO infrastructure, you 'should' log him out locally too.
     */
    public function sls()
    {
        $error = $this->saml2Auth->sls(config('saml2_settings.retrieveParametersFromServer'));
        if (!empty($error)) {
            throw new \Exception("Could not log out");
        }

        return redirect(config('saml2_settings.logoutRoute')); //may be set a configurable default
    }

    /**
     * This initiates a logout request across all the SSO infrastructure.
     */
    public function logout(Request $request)
    {
        $returnTo = $request->query('returnTo');
        $sessionIndex = $request->query('sessionIndex');
        $nameId = $request->query('nameId');
        $this->saml2Auth->logout($returnTo, $nameId, $sessionIndex); //will actually end up in the sls endpoint
        //does not return
    }


    /**
     * This initiates a login request
     */
    public function login()
    {
        $this->saml2Auth->login(config('saml2_settings.loginRoute'));
    }

    /**
     * Gets the HL7 message from the user request
     *
     * @param   Saml2User     $user
     * @return  String
     */
    private function getHL7MessageFromRequest( $user )
    {
        $attributes = $user->getAttributes();

        if( !array_key_exists('RequestMessage', $attributes) || sizeof($attributes['RequestMessage']) === 0 )
        {
            return null;
        }

        return $attributes['RequestMessage'][0];
    }

    /**
     * Get the user model using the email on request
     *
     * @param   Saml2User   $user
     * @return  User
     */
    private function getUserFromRequest( $samlUser )
    {
        $email = $samlUser->getAttributes()['Email'][0];

        // Find a node with the attribute Name set as Email, after find the text node that contains the email
        $user = User::whereUsername( $email )->first();
        if ( is_null($user) )
        {
            throw new Saml2UserNotPresentException( "Saml request with username {$username} does not have an user on AristaMD" );
        }
        return $user;
    }

    /**
     * Get the query params for the request object
     *
     * @param   Request   $request
     * @return  String
     */
    public function getUrlParamString( $request )
    {
        if( empty($request) || empty($request->id) )
        {
            return "";
        }

        $recordType = null;

        switch ( get_class($request) )
        {
            case 'App\Models\EConsult':
                $recordType = 'econsult';
                break;
            case 'App\Models\Referral':
                $recordType = 'referral';
                break;
            default:
                $recordType = null;
                break;
        }

        return "&record_type=$recordType&record_id=$request->id";
    }


    /**
     * Checks if there is an HL7 message, process the message and returns the query parameter string
     *
     * @param   Saml2User   $user
     * @return  String
     */
    private function processRequestMessage( $user, $redirectUrl )
    {
        try
        {
            $requestQueryParams = '';
            $message = $this->getHL7MessageFromRequest( $user );
            if( !empty($message) )
            {
                $appUser = $this->getUserFromRequest( $user );
                Auth::onceUsingId($appUser->id);
                $request = HL7::createRequest( $message, $appUser );
                $requestQueryParams = $this->getUrlParamString( $request );
            }
            return redirect( $redirectUrl . $requestQueryParams );
        }
        // In order to capture the exception is required to explicitly use the Class Name
        catch( InvalidHL7SegmentException $e )
        {
            return $this->processError( $e->getMessage() );
        }
        catch( InvalidMessageHL7Exception $e )
        {
            return $this->processError( $e->getMessage() );
        }
        catch( PermissionDeniedException $e )
        {
            return $this->processError( $e->getMessage() );
        }
        catch( MissingHL7OrganizationException $e )
        {
            return $this->processError( $e->getMessage() );
        }
        catch( MissingHL7SpecialtyException $e )
        {
            return $this->processError( $e->getMessage() );
        }
        catch( MissingHL7ChiefComplaintException $e )
        {
            return $this->processError( $e->getMessage() );
        }
        catch( MissingHL7WorkupChecklistException $e )
        {
            return $this->processError( $e->getMessage() );
        }
        catch(Exception $e)
        {
            return $this->processError( $e->getMessage() );
        }
    }

    /**
     * Process error, add logs and redirect to the error url
     *
     * @params  String      $errorMessage
     * @return  Redirect
     */
    private function processError( $errorMessage )
    {
        logger()->error('Saml2 error_detail', ['error' => $errorMessage]);
        session()->flash('saml2_error_detail', [$errorMessage]);
        return redirect( $this->getErrorRedirectionUrl(config('saml2_settings.errorRoute'), $errorMessage) );
    }

    /**
     * Gets Saml2 user from request
     *
     * @return  Saml2User
     */
    private function getUser()
    {
        try
        {
            return $this->saml2Auth->getSaml2User();
        }
        catch(Exception $e)
        {
            logger()->error('Saml2 error_detail', ['error' => $e->getMessage()]);
            session()->flash('saml2_error_detail', [$e->getMessage()]);
            return redirect( $this->getErrorRedirectionUrl(config('saml2_settings.errorRoute'), $e->getMessage()) );
        }
    }

    /**
     * Get error redirection url with required params
     *
     * @param   String  $url            Redirection url
     * @param   String  $errorMessage   Error message string
     * @return  String                  Redirection url
     */
    private function getErrorRedirectionUrl( $url, $errorMessage )
    {
        $errors = base64_encode( json_encode(explode(PHP_EOL, $errorMessage)) );
        return $url . '&' . http_build_query( ['error-message'=>$errors,'base64'=>true] );
    }
}
