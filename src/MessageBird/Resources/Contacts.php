<?php

namespace MessageBird\Resources;

use InvalidArgumentException;
use MessageBird\Common;
use MessageBird\Objects;

/**
 * Class Contacts
 *
 * @package MessageBird\Resources
 */
class Contacts extends Base
{
    public function __construct(Common\HttpClient $httpClient)
    {
        $this->setObject(new Objects\Contact());
        $this->setResourceName('contacts');

        parent::__construct($httpClient);
    }

    /**
     * @param mixed $object
     * @param mixed $id
     *
     * @return Objects\Balance|Objects\Conversation\Conversation|Objects\Hlr|Objects\Lookup|Objects\Message|Objects\Verify|Objects\VoiceMessage|null ->object
     *
     * @internal param array $parameters
     */
    public function update($object, $id)
    {
        $objVars = get_object_vars($object);
        $body = [];
        foreach ($objVars as $key => $value) {
            if ($value !== null) {
                $body[$key] = $value;
            }
        }

        $resourceName = $this->resourceName . ($id ? '/' . $id : null);
        $body = json_encode($body, JSON_THROW_ON_ERROR);

        [, , $body] = $this->httpClient->performHttpRequest(
            Common\HttpClient::REQUEST_PATCH,
            $resourceName,
            false,
            $body
        );
        return $this->processRequest($body);
    }

    /**
     * @param mixed $id
     * @param array|null $parameters
     *
     * @return Objects\Balance|Objects\BaseList|Objects\Conversation\Conversation|Objects\Hlr|Objects\Lookup|Objects\Message|Objects\Verify|Objects\VoiceMessage|null ->object
     */
    public function getMessages($id, $parameters = [])
    {
        if ($id === null) {
            throw new InvalidArgumentException('No contact id provided.');
        }

        $this->setObject(new Objects\Message());
        $this->setResourceName($this->resourceName . '/' . $id . '/messages');
        return $this->getList($parameters);
    }

    /**
     * @param mixed $id
     * @param array|null $parameters
     *
     * @return Objects\Balance|Objects\BaseList|Objects\Conversation\Conversation|Objects\Hlr|Objects\Lookup|Objects\Message|Objects\Verify|Objects\VoiceMessage|null ->object
     */
    public function getGroups($id, $parameters = [])
    {
        if ($id === null) {
            throw new InvalidArgumentException('No contact id provided.');
        }

        $this->setObject(new Objects\Group());
        $this->setResourceName($this->resourceName . '/' . $id . '/groups');
        return $this->getList($parameters);
    }
}
